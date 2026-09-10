from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import requests.adapters
import structlog
from requests.auth import AuthBase, HTTPBasicAuth, HTTPDigestAuth

from stealthix.core.errors import AuthError, CredentialError, NetworkError, StealthixError
from stealthix.core.session import ScanSession
from stealthix.crawler.form_parser import DiscoveredForm, parse_forms
from stealthix.detection.rest_api import method_uses_body

logger = logging.getLogger(__name__)

_USERNAME_HINTS = ("user", "username", "email", "login", "identifier")
_PASSWORD_HINTS = ("pass", "password", "passwd", "pwd")
_TOKEN_KEYS = ("access_token", "token", "id_token", "jwt")
_META_CSRF_RE = re.compile(
    r"<meta[^>]+(?:name|id)=[\"']([^\"']*(?:csrf|token)[^\"']*)[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


def _normalized_auth_type(session: ScanSession) -> str | None:
    raw = (session.config.auth_type or "").strip().lower()
    if raw:
        return raw
    if session.config.auth_token:
        return "bearer"
    return None


def _auth_config(session: ScanSession) -> dict[str, Any]:
    payload = session.config.auth_config if isinstance(session.config.auth_config, dict) else {}
    return dict(payload)


def _auth_metadata(session: ScanSession) -> dict[str, Any]:
    auth_meta = session.metadata.setdefault("auth", {})
    if not isinstance(auth_meta, dict):
        auth_meta = {}
        session.metadata["auth"] = auth_meta
    return auth_meta


def has_auth(session: ScanSession) -> bool:
    return _normalized_auth_type(session) is not None


def _sync_session_cookies(session: ScanSession, client: requests.Session) -> None:
    cookie_dict = requests.utils.dict_from_cookiejar(client.cookies)
    if cookie_dict:
        session.config.cookies.update({str(key): str(value) for key, value in cookie_dict.items()})
    auth_meta = _auth_metadata(session)
    auth_meta["cookies"] = dict(session.config.cookies)
    auth_meta["cookie_count"] = len(session.config.cookies)


def get_requests_client(session: ScanSession) -> requests.Session:
    client = session.runtime.get("requests_client")
    if isinstance(client, requests.Session):
        return client
    client = requests.Session()
    if (
        session.config.worker_count() > 1
        or session.config.pool_connections is not None
        or session.config.pool_maxsize is not None
    ):
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=session.config.effective_pool_connections(),
            pool_maxsize=session.config.effective_pool_maxsize(),
            max_retries=0,
        )
        client.mount("http://", adapter)
        client.mount("https://", adapter)
    if session.config.proxy:
        client.proxies.update({"http": session.config.proxy, "https": session.config.proxy})
    for key, value in session.config.cookies.items():
        client.cookies.set(str(key), str(value))
    session.runtime["requests_client"] = client
    return client


def _extract_json_path(payload: Any, path: str | None) -> Any:
    if not path:
        return None
    current = payload
    for part in [item.strip() for item in path.split(".") if item.strip()]:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            idx = int(part)
            current = current[idx] if 0 <= idx < len(current) else None
        else:
            return None
    return current


def _token_from_response(response: requests.Response, config: dict[str, Any]) -> str | None:
    json_path = (
        str(config.get("token_json_path") or config.get("refresh_token_path") or "").strip() or None
    )
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if payload is not None:
        if json_path:
            found = _extract_json_path(payload, json_path)
            if found not in (None, ""):
                return str(found)
        if isinstance(payload, dict):
            for key in _TOKEN_KEYS:
                if payload.get(key) not in (None, ""):
                    return str(payload[key])
    header_name = str(config.get("token_header") or "Authorization").strip()
    header_value = response.headers.get(header_name)
    if header_value:
        scheme = str(config.get("scheme") or "Bearer").strip()
        prefix = f"{scheme} " if scheme else ""
        if prefix and header_value.startswith(prefix):
            return header_value[len(prefix) :].strip()
        return header_value.strip()
    return None


def _apply_token(session: ScanSession, token: str) -> None:
    session.config.auth_token = token
    session.creds.add("auth_token", token)
    config = _auth_config(session)
    config["token"] = token
    session.config.auth_config = config
    auth_meta = _auth_metadata(session)
    auth_meta["authenticated"] = True
    auth_meta["auth_type"] = _normalized_auth_type(session) or "bearer"
    auth_meta["last_refresh_at"] = time.time()
    auth_meta["session_expired"] = False


def _header_name_and_value(session: ScanSession) -> tuple[str, str] | None:
    auth_type = _normalized_auth_type(session)
    if auth_type not in {"bearer", "jwt", "token"} and not session.config.auth_token:
        return None
    config = _auth_config(session)
    token = str(
        config.get("token") or session.config.auth_token or session.creds.get("auth_token") or ""
    ).strip()
    if not token:
        return None
    header_name = str(
        config.get("header_name") or config.get("token_header") or "Authorization"
    ).strip()
    scheme = str(config.get("scheme") or "Bearer").strip()
    return header_name, f"{scheme} {token}".strip() if scheme else token


def _request_client_response(
    session: ScanSession,
    client: requests.Session,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    body_format: str = "form",
    auth: AuthBase | Any | None = None,
    allow_redirects: bool = True,
) -> requests.Response:
    request_headers = dict(headers or {})
    if body_format == "json":
        request_headers.setdefault("Content-Type", "application/json")
    response = client.request(
        method.upper(),
        url,
        headers=request_headers,
        data=(data or {}) if body_format != "json" or method.upper() == "GET" else None,
        json=(data or {}) if body_format == "json" and method.upper() != "GET" else None,
        timeout=session.config.timeout,
        verify=session.config.verify_tls,
        auth=auth,
        allow_redirects=allow_redirects,
    )
    _sync_session_cookies(session, client)
    return response


def _guess_username_field(form: DiscoveredForm) -> str | None:
    for field in form.fields:
        name = field.name.lower()
        if any(token in name for token in _USERNAME_HINTS):
            return field.name
    for field in form.fields:
        if field.field_type.lower() in {"text", "email"}:
            return field.name
    return None


def _guess_password_field(form: DiscoveredForm) -> str | None:
    for field in form.fields:
        name = field.name.lower()
        if field.field_type.lower() == "password" or any(
            token in name for token in _PASSWORD_HINTS
        ):
            return field.name
    return None


def _select_login_form(
    forms: list[DiscoveredForm], config: dict[str, Any]
) -> DiscoveredForm | None:
    form_id = str(config.get("form_id") or "").strip()
    form_name = str(config.get("form_name") or "").strip()
    action_contains = (
        str(config.get("action_contains") or config.get("login_path") or "").strip().lower()
    )
    for form in forms:
        if form_id and form.form_id == form_id:
            return form
        if form_name and form.form_name == form_name:
            return form
        if action_contains and action_contains in form.action.lower():
            return form
    for form in forms:
        if _guess_password_field(form):
            return form
    return forms[0] if forms else None


def _coerce_extra_fields(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items() if str(key).strip()}
    if isinstance(value, list):
        parsed: dict[str, str] = {}
        for item in value:
            if isinstance(item, dict):
                parsed.update({str(key): str(val) for key, val in item.items() if str(key).strip()})
            elif isinstance(item, str) and ("=" in item or ":" in item):
                sep = "=" if "=" in item else ":"
                key, raw = item.split(sep, 1)
                if key.strip():
                    parsed[key.strip()] = raw.strip()
        return parsed
    return {}


def _build_login_payload(
    form: DiscoveredForm, config: dict[str, Any], username: str, password: str
) -> dict[str, Any]:
    payload = {field.name: field.resolved_value() for field in form.fields if field.name}
    username_field = str(config.get("username_field") or "").strip() or _guess_username_field(form)
    password_field = str(config.get("password_field") or "").strip() or _guess_password_field(form)
    if not username_field or not password_field:
        raise ValueError("Could not determine login form username/password fields.")
    payload[username_field] = username
    payload[password_field] = password
    payload.update(_coerce_extra_fields(config.get("extra_fields")))
    return payload


def _auth_success(
    response: requests.Response, config: dict[str, Any], session: ScanSession
) -> bool:
    if response.status_code in {401, 403}:
        return False
    body = response.text or ""
    success_indicator = str(config.get("success_indicator") or "").strip().lower()
    failure_indicator = str(config.get("failure_indicator") or "").strip().lower()
    if failure_indicator and failure_indicator in body.lower():
        return False
    if success_indicator:
        return success_indicator in body.lower()
    return (response.status_code is not None and response.status_code < 400) and bool(
        session.config.cookies or response.cookies
    )


def _load_script_module(path: str):
    target = Path(path).expanduser().resolve()
    spec = importlib.util.spec_from_file_location(
        f"stealthix_auth_{abs(hash(str(target)))}", target
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"Unable to load auth script: {target}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apply_script_result(session: ScanSession, result: Any) -> None:
    if not isinstance(result, dict):
        return
    if isinstance(result.get("headers"), dict):
        session.config.headers.update(
            {str(k): str(v) for k, v in result["headers"].items() if str(k).strip()}
        )
    if isinstance(result.get("cookies"), dict):
        session.config.cookies.update(
            {str(k): str(v) for k, v in result["cookies"].items() if str(k).strip()}
        )
    if result.get("auth_token"):
        _apply_token(session, str(result["auth_token"]))
    if isinstance(result.get("auth_config"), dict):
        auth_config = _auth_config(session)
        auth_config.update(result["auth_config"])
        session.config.auth_config = auth_config
    auth_meta = _auth_metadata(session)
    if isinstance(result.get("metadata"), dict):
        auth_meta.update(result["metadata"])
    if isinstance(result.get("creds"), dict):
        for key, value in result["creds"].items():
            if str(key).strip():
                session.creds.add(str(key), str(value))


def _run_custom_script(
    session: ScanSession, *, function_name: str, reason: str | None = None
) -> bool:
    config = _auth_config(session)
    script_path = str(config.get("script") or "").strip()
    if not script_path:
        raise ValueError("Custom auth requires auth_config.script")
    module = session.runtime.get("auth_script_module")
    if module is None or str(getattr(module, "__file__", "")) != str(
        Path(script_path).expanduser().resolve()
    ):
        module = _load_script_module(script_path)
        session.runtime["auth_script_module"] = module
    func = getattr(module, function_name, None) or getattr(module, "authenticate", None)
    if not callable(func):
        raise ValueError(
            f"Auth script '{script_path}' does not expose a callable '{function_name}' or 'authenticate'."
        )
    client = get_requests_client(session)
    result = func(
        session,
        {
            "reason": reason,
            "auth_type": _normalized_auth_type(session),
            "auth_config": config,
            "cookies": dict(session.config.cookies),
            "headers": dict(session.config.headers),
            "client": client,
        },
    )
    _apply_script_result(session, result)
    _sync_session_cookies(session, client)
    auth_meta = _auth_metadata(session)
    auth_meta["authenticated"] = True
    auth_meta["auth_type"] = "script"
    auth_meta["authenticated_at"] = time.time()
    auth_meta["session_expired"] = False
    return True


def _bearer_refresh(session: ScanSession, *, reason: str | None = None) -> bool:
    config = _auth_config(session)
    refresh_url = str(config.get("refresh_url") or "").strip()
    token = str(
        config.get("token") or session.config.auth_token or session.creds.get("auth_token") or ""
    ).strip()
    if not refresh_url:
        if token:
            _apply_token(session, token)
            return False
        raise ValueError("Bearer authentication requires auth_token or auth_config.refresh_url")
    client = get_requests_client(session)
    refresh_method = str(config.get("refresh_method") or "POST").upper()
    refresh_body_format = str(config.get("refresh_body_format") or "json").lower()
    refresh_headers = (
        config.get("refresh_headers") if isinstance(config.get("refresh_headers"), dict) else {}
    )
    refresh_headers = refresh_headers if isinstance(refresh_headers, dict) else {}
    request_headers = {
        str(key): str(value) for key, value in refresh_headers.items() if str(key).strip()
    }
    if token and not config.get("refresh_without_token"):
        scheme = str(config.get("scheme") or "Bearer").strip()
        request_headers.setdefault(
            "Authorization", f"{scheme} {token}".strip() if scheme else token
        )
    refresh_body = (
        config.get("refresh_body") if isinstance(config.get("refresh_body"), dict) else {}
    )
    response = _request_client_response(
        session,
        client,
        refresh_method,
        urljoin(session.config.base_url, refresh_url),
        headers=request_headers,
        data=refresh_body,
        body_format=refresh_body_format,
        auth=None,
    )
    new_token = _token_from_response(response, config)
    if not new_token:
        raise ValueError("Refresh endpoint did not return a token.")
    _apply_token(session, new_token)
    auth_meta = _auth_metadata(session)
    auth_meta["refresh_reason"] = reason
    auth_meta["refresh_status"] = response.status_code
    return True


def _form_auth(session: ScanSession, *, force: bool = False, reason: str | None = None) -> bool:
    auth_meta = _auth_metadata(session)
    if not force and auth_meta.get("authenticated") and session.config.cookies:
        return False
    config = _auth_config(session)
    username = str(config.get("username") or session.creds.get("username") or "").strip()
    password = str(config.get("password") or session.creds.get("password") or "").strip()
    if not username or not password:
        raise ValueError("Form authentication requires username and password.")
    session.creds.add("username", username)
    session.creds.add("password", password)
    login_url = urljoin(
        session.config.base_url, str(config.get("login_url") or session.config.base_url)
    )
    client = get_requests_client(session)
    login_headers = config.get("headers") if isinstance(config.get("headers"), dict) else {}
    login_headers = login_headers if isinstance(login_headers, dict) else {}
    page_response = _request_client_response(
        session,
        client,
        "GET",
        login_url,
        headers={str(k): str(v) for k, v in login_headers.items()},
    )
    forms = parse_forms(login_url, page_response.text)
    login_form = _select_login_form(forms, config)
    if login_form is None:
        raise ValueError(f"No login form detected at {login_url}")
    payload = _build_login_payload(login_form, config, username, password)
    submit_response = _request_client_response(
        session,
        client,
        login_form.method,
        login_form.action,
        headers={str(k): str(v) for k, v in login_headers.items()},
        data=payload,
        body_format="form",
        auth=None,
    )
    verify_url = str(config.get("verify_url") or "").strip()
    final_response = submit_response
    if verify_url:
        final_response = _request_client_response(
            session,
            client,
            "GET",
            urljoin(session.config.base_url, verify_url),
            headers={str(k): str(v) for k, v in login_headers.items()},
        )
    if not _auth_success(final_response, config, session):
        raise ValueError(
            f"Authentication failed for {login_url} (status {final_response.status_code})."
        )
    auth_meta.update(
        {
            "authenticated": True,
            "auth_type": "form",
            "authenticated_at": time.time(),
            "login_url": login_url,
            "form_action": login_form.action,
            "reason": reason,
            "session_expired": False,
        }
    )
    return True


def requests_auth_for_session(session: ScanSession) -> AuthBase | tuple[str, str] | None:
    auth_type = _normalized_auth_type(session)
    config = _auth_config(session)
    username = str(config.get("username") or session.creds.get("username") or "").strip()
    password = str(config.get("password") or session.creds.get("password") or "").strip()
    if auth_type == "basic":
        if not username or not password:
            raise ValueError("Basic authentication requires username and password.")
        session.creds.add("username", username)
        session.creds.add("password", password)
        return HTTPBasicAuth(username, password)
    if auth_type == "digest":
        if not username or not password:
            raise ValueError("Digest authentication requires username and password.")
        session.creds.add("username", username)
        session.creds.add("password", password)
        return HTTPDigestAuth(username, password)
    if auth_type == "ntlm":
        if not username or not password:
            raise ValueError("NTLM authentication requires username and password.")
        try:
            from requests_ntlm import HttpNtlmAuth  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on optional package
            raise ValueError(
                "NTLM authentication requires the optional 'requests-ntlm' package."
            ) from exc
        except Exception as exc:  # pragma: no cover - depends on optional package
            logger.error(f"Failed to import requests_ntlm: {exc}", exc_info=True)
            raise ValueError(
                "NTLM authentication requires the optional 'requests-ntlm' package."
            ) from exc
        session.creds.add("username", username)
        session.creds.add("password", password)
        return HttpNtlmAuth(username, password)
    return None


def ensure_authenticated(
    session: ScanSession, *, force: bool = False, reason: str | None = None
) -> bool:
    auth_type = _normalized_auth_type(session)
    if not auth_type:
        return False
    auth_meta = _auth_metadata(session)
    if auth_type in {"bearer", "jwt", "token"}:
        return (
            _bearer_refresh(session, reason=reason)
            if force
            else _bearer_refresh(session, reason=reason)
            if not session.config.auth_token
            else False
        )
    if auth_type == "form":
        return _form_auth(session, force=force, reason=reason)
    if auth_type == "script":
        return _run_custom_script(
            session, function_name="refresh_auth" if force else "authenticate", reason=reason
        )
    if auth_type in {"basic", "digest", "ntlm"}:
        _ = requests_auth_for_session(session)
        auth_meta.update(
            {
                "authenticated": True,
                "auth_type": auth_type,
                "authenticated_at": time.time(),
                "session_expired": False,
            }
        )
        return False
    raise ValueError(f"Unsupported auth type: {auth_type}")


def refresh_auth(session: ScanSession, *, force: bool = True, reason: str | None = None) -> bool:
    return ensure_authenticated(session, force=force, reason=reason)


def _extract_csrf_tokens_from_html(
    page_url: str, html: str, *, form_action: str | None = None
) -> dict[str, str]:
    forms = parse_forms(page_url, html)
    candidates = forms
    if form_action:
        lowered = form_action.lower()
        matching = [form for form in forms if lowered in form.action.lower()]
        if matching:
            candidates = matching
    tokens: dict[str, str] = {}
    for form in candidates:
        for field in form.fields:
            if field.csrf and field.name and field.resolved_value():
                tokens[field.name] = field.resolved_value()
    for name, value in _META_CSRF_RE.findall(html or ""):
        if name and value:
            tokens.setdefault(name, value)
    return tokens


def inject_csrf_tokens(
    session: ScanSession, request_url: str, data: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return data
    config = _auth_config(session)
    csrf_enabled = bool(config.get("csrf_enabled", has_auth(session)))
    if not csrf_enabled:
        return data
    csrf_field = str(config.get("csrf_field") or "").strip() or None
    if csrf_field and str(data.get(csrf_field) or "").strip():
        return data
    auth_meta = _auth_metadata(session)
    cached = auth_meta.get("csrf_tokens") if isinstance(auth_meta.get("csrf_tokens"), dict) else {}
    cached = cached if isinstance(cached, dict) else {}
    tokens = cached.get(request_url) if isinstance(cached.get(request_url), dict) else None
    if tokens is None:
        source_url = urljoin(
            session.config.base_url,
            str(config.get("csrf_url") or request_url or session.config.base_url),
        )
        client = get_requests_client(session)
        response = _request_client_response(
            session, client, "GET", source_url, headers=dict(session.config.headers)
        )
        tokens = _extract_csrf_tokens_from_html(source_url, response.text, form_action=request_url)
        if isinstance(cached, dict):
            cached[request_url] = tokens
        auth_meta["csrf_tokens"] = cached
    if not tokens:
        return data
    merged = dict(data)
    if csrf_field:
        if csrf_field in tokens and not merged.get(csrf_field):
            merged[csrf_field] = tokens[csrf_field]
        return merged
    for key, value in tokens.items():
        if key not in merged or merged.get(key) in (None, ""):
            merged[key] = value
    return merged


def prepare_request_auth(
    session: ScanSession,
    *,
    url: str,
    headers: dict[str, str],
    data: dict[str, Any] | None,
    method: str,
    body_format: str,
) -> tuple[dict[str, str], dict[str, Any] | None, AuthBase | tuple[str, str] | None]:
    request_headers = dict(headers)
    if has_auth(session):
        ensure_authenticated(session)
    header_pair = _header_name_and_value(session)
    if header_pair is not None:
        request_headers.setdefault(header_pair[0], header_pair[1])
    request_data = data
    if method_uses_body(method) and body_format in {"form", "json", "xml"}:
        request_data = inject_csrf_tokens(session, url, request_data)
    return request_headers, request_data, requests_auth_for_session(session)


def handle_auth_failure(session: ScanSession, *, status_code: int | None, url: str) -> bool:
    if status_code not in {401, 403} or not has_auth(session):
        return False
    auth_meta = _auth_metadata(session)
    auth_meta["session_expired"] = True
    auth_meta["last_failure_status"] = status_code
    auth_meta["last_failure_url"] = url
    try:
        refreshed = refresh_auth(session, force=True, reason=f"HTTP {status_code} from {url}")
    except (ValueError, KeyError, ConnectionError) as exc:
        logger.warning(f"Auth refresh failed: {exc}")
        auth_meta["last_error"] = str(exc)
        return False
    except AuthError as exc:
        logger.error(f"Unexpected auth refresh error: {exc}", exc_info=True)
        auth_meta["last_error"] = str(exc)
        return False
    auth_meta["session_expired"] = False
    auth_meta["reauthenticated"] = bool(refreshed or auth_meta.get("authenticated"))
    return True


__all__ = [
    "ensure_authenticated",
    "get_requests_client",
    "handle_auth_failure",
    "has_auth",
    "inject_csrf_tokens",
    "prepare_request_auth",
    "refresh_auth",
    "requests_auth_for_session",
]
