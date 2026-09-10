"""Redis-based task queue for distributed scanning."""

from __future__ import annotations

import logging
import time
from typing import Any, cast

try:
    import redis
    from redis import Redis
    from redis.exceptions import ConnectionError, RedisError

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from stealthix.distributed.models import ScanTask, TaskResult

logger = logging.getLogger(__name__)

# Redis key prefixes
TASK_QUEUE_KEY = "stealthix:task_queue"
TASK_PAYLOAD_KEY = "stealthix:task_payloads"
TASK_ATTEMPTS_KEY = "stealthix:task_attempts"
TASK_LEASE_KEY = "stealthix:task_leases"
TASK_LEASE_WORKER_KEY = "stealthix:task_lease_workers"
TASK_PRIORITY_KEY = "stealthix:task_priorities"
TASK_SCAN_KEY = "stealthix:task_scans"
TASK_DEAD_LETTER_KEY = "stealthix:task_dead_letter"
TASK_STATUS_KEY = "stealthix:task_status:"
TASK_RESULT_KEY = "stealthix:task_result:"
SCAN_CANCELLED_KEY = "stealthix:scan_cancelled:"
WORKER_HEARTBEAT_KEY = "stealthix:worker_heartbeat:"

DEQUEUE_TASK_SCRIPT = """
local queue_key = KEYS[1]
local payload_key = KEYS[2]
local attempts_key = KEYS[3]
local lease_key = KEYS[4]
local lease_worker_key = KEYS[5]
local status_prefix = KEYS[6]
local scan_key = KEYS[7]
local cancelled_prefix = KEYS[8]

local worker_id = ARGV[1]
local lease_expires_at = tonumber(ARGV[2])

while true do
    local entry = redis.call("ZRANGE", queue_key, 0, 0)
    if #entry == 0 then
        return nil
    end

    local task_id = entry[1]
    local payload = redis.call("HGET", payload_key, task_id)
    redis.call("ZREM", queue_key, task_id)

    if payload then
        local scan_id = redis.call("HGET", scan_key, task_id)
        if scan_id and redis.call("GET", cancelled_prefix .. scan_id) then
            redis.call("SET", status_prefix .. task_id, "cancelled")
        else
            local attempts = redis.call("HINCRBY", attempts_key, task_id, 1)
            redis.call("ZADD", lease_key, lease_expires_at, task_id)
            redis.call("HSET", lease_worker_key, task_id, worker_id)
            redis.call("SET", status_prefix .. task_id, "running")
            redis.call("SET", status_prefix .. task_id .. ":worker", worker_id)
            return {task_id, payload, tostring(attempts)}
        end
    end
end
"""


class RedisTaskQueue:
    """Redis-based task queue for distributed scanning."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str | None = None,
        decode_responses: bool = True,
        lease_ttl: int = 300,
        max_retries: int = 3,
    ) -> None:
        """Initialize Redis task queue.

        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            decode_responses: Whether to decode responses to strings
            lease_ttl: Seconds a worker owns a dequeued task before it can be requeued
            max_retries: Maximum execution attempts before dead-lettering a task
        """
        if not REDIS_AVAILABLE:
            raise ImportError(
                "redis package is required for distributed mode. Install with: pip install redis"
            )

        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.decode_responses = decode_responses
        self.lease_ttl = lease_ttl
        self.max_retries = max_retries
        self._redis: Redis | None = None

    def connect(self) -> None:
        """Connect to Redis."""
        try:
            self._redis = Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=self.decode_responses,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            # Test connection
            self._redis.ping()
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
        except ConnectionError as e:
            raise ConnectionError(
                f"Failed to connect to Redis at {self.host}:{self.port}: {e}"
            ) from e

    def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis:
            self._redis.close()
            self._redis = None
            logger.info("Disconnected from Redis")

    def _ensure_connected(self) -> Redis:
        """Ensure Redis connection is active."""
        if self._redis is None:
            self.connect()
        return cast(Redis, self._redis)

    def enqueue_task(self, task: ScanTask) -> str:
        """Enqueue a scan task to the queue.

        Args:
            task: ScanTask to enqueue

        Returns:
            Task ID
        """
        redis = self._ensure_connected()
        task_json = task.model_dump_json()
        redis.hset(TASK_PAYLOAD_KEY, task.task_id, task_json)
        redis.hset(TASK_PRIORITY_KEY, task.task_id, str(task.priority))
        redis.hset(TASK_ATTEMPTS_KEY, task.task_id, "0")
        if task.scan_id:
            redis.hset(TASK_SCAN_KEY, task.task_id, task.scan_id)
        # Add task id to the ready queue with priority (lower score = higher priority).
        redis.zadd(TASK_QUEUE_KEY, {task.task_id: task.priority})
        # Set initial status
        redis.set(f"{TASK_STATUS_KEY}{task.task_id}", task.status)
        logger.info(f"Enqueued task {task.task_id} for target {task.target}")
        return task.task_id

    def dequeue_task(self, worker_id: str, timeout: int = 30) -> ScanTask | None:
        """Dequeue and lease a task from the queue.

        Args:
            worker_id: Worker ID
            timeout: Maximum seconds to wait for a ready task

        Returns:
            ScanTask or None if timeout
        """
        redis = self._ensure_connected()
        deadline = time.monotonic() + max(0, timeout)

        while True:
            self.requeue_expired_leases()
            lease_expires_at = time.time() + self.lease_ttl
            result = redis.eval(
                DEQUEUE_TASK_SCRIPT,
                8,
                TASK_QUEUE_KEY,
                TASK_PAYLOAD_KEY,
                TASK_ATTEMPTS_KEY,
                TASK_LEASE_KEY,
                TASK_LEASE_WORKER_KEY,
                TASK_STATUS_KEY,
                TASK_SCAN_KEY,
                SCAN_CANCELLED_KEY,
                worker_id,
                lease_expires_at,
            )
            if result:
                result_list = cast(list[Any], result)
                task_id, task_json, attempts_raw = result_list
                task_id = self._to_str(task_id)
                attempts = int(self._to_str(attempts_raw))
                task = ScanTask.model_validate_json(self._to_str(task_json))
                task.status = "running"
                logger.info(
                    "Worker %s leased task %s (attempt %s/%s)",
                    worker_id,
                    task_id,
                    attempts,
                    self.max_retries,
                )
                return task

            if timeout <= 0 or time.monotonic() >= deadline:
                return None
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))

    def get_task_status(self, task_id: str) -> str | None:
        """Get task status.

        Args:
            task_id: Task ID

        Returns:
            Task status or None
        """
        redis = self._ensure_connected()
        result = redis.get(f"{TASK_STATUS_KEY}{task_id}")
        return cast(str | None, result)

    def update_task_progress(self, task_id: str, progress: float) -> None:
        """Update task progress.

        Args:
            task_id: Task ID
            progress: Progress value (0-1)
        """
        redis = self._ensure_connected()
        redis.set(f"{TASK_STATUS_KEY}{task_id}:progress", str(progress))

    def mark_task_complete(self, task_id: str, result: TaskResult) -> None:
        """Acknowledge a leased task as complete and store its result.

        Args:
            task_id: Task ID
            result: Task result
        """
        redis = self._ensure_connected()
        self._remove_lease(redis, task_id)
        redis.set(f"{TASK_STATUS_KEY}{task_id}", "completed")
        redis.set(f"{TASK_RESULT_KEY}{task_id}", result.model_dump_json())
        logger.info(f"Task {task_id} marked as complete")

    def mark_task_failed(self, task_id: str, error: str) -> None:
        """Mark a leased task failed, requeue it, or dead-letter it.

        Args:
            task_id: Task ID
            error: Error message
        """
        redis = self._ensure_connected()
        attempts = self._task_attempts(redis, task_id)
        self._remove_lease(redis, task_id)
        redis.set(f"{TASK_RESULT_KEY}{task_id}:error", error)

        if attempts >= self.max_retries:
            self._dead_letter(redis, task_id, error)
            logger.error("Task %s dead-lettered after %s attempts: %s", task_id, attempts, error)
            return

        self._requeue_task(redis, task_id, status="pending")
        logger.warning(
            "Task %s failed on attempt %s/%s and was requeued: %s",
            task_id,
            attempts,
            self.max_retries,
            error,
        )

    def mark_task_cancelled(self, task_id: str) -> None:
        """Acknowledge a task as cancelled without retrying it."""
        redis = self._ensure_connected()
        self._remove_lease(redis, task_id)
        redis.zrem(TASK_QUEUE_KEY, task_id)
        redis.set(f"{TASK_STATUS_KEY}{task_id}", "cancelled")
        redis.set(f"{TASK_RESULT_KEY}{task_id}:error", "scan cancelled")
        logger.info("Task %s marked as cancelled", task_id)

    def get_task_result(self, task_id: str) -> TaskResult | None:
        """Get task result.

        Args:
            task_id: Task ID

        Returns:
            TaskResult or None
        """
        redis = self._ensure_connected()
        result_json = redis.get(f"{TASK_RESULT_KEY}{task_id}")
        if result_json:
            return TaskResult.model_validate_json(cast(str, result_json))
        return None

    def update_worker_heartbeat(self, worker_id: str) -> None:
        """Update worker heartbeat.

        Args:
            worker_id: Worker ID
        """
        redis = self._ensure_connected()
        redis.set(f"{WORKER_HEARTBEAT_KEY}{worker_id}", str(time.time()), ex=60)

    def get_active_workers(self, timeout: int = 60) -> list[str]:
        """Get list of active workers.

        Args:
            timeout: Worker timeout in seconds

        Returns:
            List of active worker IDs
        """
        redis = self._ensure_connected()
        current_time = time.time()
        keys = redis.keys(f"{WORKER_HEARTBEAT_KEY}*") or []
        active_workers = []
        for key in keys if isinstance(keys, list) else []:
            key_str = str(key) if not isinstance(key, str) else key
            heartbeat = redis.get(key_str)
            if heartbeat:
                heartbeat_str = (
                    str(heartbeat) if not isinstance(heartbeat, (str, bytes)) else heartbeat
                )
                last_seen = float(heartbeat_str)
                if current_time - last_seen < timeout:
                    worker_id = key_str.replace(WORKER_HEARTBEAT_KEY, "")
                    active_workers.append(worker_id)
        return active_workers

    def requeue_expired_leases(self) -> int:
        """Requeue expired leases or dead-letter exhausted tasks.

        Returns:
            Number of expired leased tasks processed
        """
        redis = self._ensure_connected()
        now = time.time()
        expired_ids = redis.zrangebyscore(TASK_LEASE_KEY, min=0, max=now) or []
        processed = 0
        for raw_task_id in expired_ids if isinstance(expired_ids, list) else []:
            task_id = self._to_str(raw_task_id)
            if self.is_task_cancelled(task_id):
                self.mark_task_cancelled(task_id)
                processed += 1
                continue
            attempts = self._task_attempts(redis, task_id)
            self._remove_lease(redis, task_id)
            if attempts >= self.max_retries:
                self._dead_letter(redis, task_id, "lease expired")
            else:
                self._requeue_task(redis, task_id, status="pending")
            processed += 1
        return processed

    def get_dead_lettered_tasks(self) -> list[ScanTask]:
        """Return dead-lettered tasks in insertion order."""
        redis = self._ensure_connected()
        task_ids = redis.zrange(TASK_DEAD_LETTER_KEY, 0, -1) or []
        tasks: list[ScanTask] = []
        for raw_task_id in task_ids if isinstance(task_ids, list) else []:
            task_id = self._to_str(raw_task_id)
            task_json = redis.hget(TASK_PAYLOAD_KEY, task_id)
            if task_json:
                task = ScanTask.model_validate_json(self._to_str(task_json))
                task.status = "dead-lettered"
                tasks.append(task)
        return tasks

    def clear_queue(self) -> int:
        """Clear all tasks from the queue.

        Returns:
            Number of tasks cleared
        """
        redis = self._ensure_connected()
        zcard_result = redis.zcard(TASK_QUEUE_KEY)
        count = int(cast(int, zcard_result or 0))
        redis.delete(TASK_QUEUE_KEY, TASK_LEASE_KEY)
        logger.info(f"Cleared {count} tasks from queue")
        return count

    def cancel_scan(self, scan_id: str, task_ids: list[str] | None = None) -> None:
        """Set scan-level cancellation state and mark known non-terminal tasks cancelled."""
        redis = self._ensure_connected()
        redis.set(f"{SCAN_CANCELLED_KEY}{scan_id}", str(time.time()))
        if task_ids:
            for task_id in task_ids:
                status = self.get_task_status(task_id)
                if status not in {"completed", "failed", "dead-lettered", "cancelled"}:
                    self.mark_task_cancelled(task_id)

    def is_scan_cancelled(self, scan_id: str | None) -> bool:
        """Return whether a scan has been cancelled."""
        if not scan_id:
            return False
        redis = self._ensure_connected()
        return redis.get(f"{SCAN_CANCELLED_KEY}{scan_id}") is not None

    def is_task_cancelled(self, task_id: str) -> bool:
        """Return whether the scan for a task has been cancelled."""
        redis = self._ensure_connected()
        scan_id = redis.hget(TASK_SCAN_KEY, task_id)
        return self.is_scan_cancelled(self._to_str(scan_id)) if scan_id else False

    def get_queue_size(self) -> int:
        """Get current queue size.

        Returns:
            Number of tasks in queue
        """
        redis = self._ensure_connected()
        result = redis.zcard(TASK_QUEUE_KEY)
        return int(cast(int, result or 0))

    @staticmethod
    def _to_str(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)

    def _task_attempts(self, redis: Redis, task_id: str) -> int:
        attempts = redis.hget(TASK_ATTEMPTS_KEY, task_id)
        return int(self._to_str(attempts)) if attempts is not None else 0

    def _remove_lease(self, redis: Redis, task_id: str) -> None:
        redis.zrem(TASK_LEASE_KEY, task_id)
        redis.hdel(TASK_LEASE_WORKER_KEY, task_id)
        redis.delete(f"{TASK_STATUS_KEY}{task_id}:worker")

    def _requeue_task(self, redis: Redis, task_id: str, *, status: str) -> None:
        priority = redis.hget(TASK_PRIORITY_KEY, task_id)
        score = int(self._to_str(priority)) if priority is not None else 0
        redis.zadd(TASK_QUEUE_KEY, {task_id: score})
        redis.set(f"{TASK_STATUS_KEY}{task_id}", status)

    def _dead_letter(self, redis: Redis, task_id: str, error: str) -> None:
        redis.zadd(TASK_DEAD_LETTER_KEY, {task_id: time.time()})
        redis.set(f"{TASK_STATUS_KEY}{task_id}", "dead-lettered")
        redis.set(f"{TASK_RESULT_KEY}{task_id}:error", error)


__all__ = ["RedisTaskQueue"]
