import os
import socket

from stealthix.oob.dns_listener import DnsCallbackListener


def _dns_query(name: str) -> bytes:
    txn_id = os.urandom(2)
    flags = b"\x01\x00"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    header = txn_id + flags + counts
    labels = []
    for part in name.split("."):
        part_b = part.encode("ascii", errors="ignore")[:63]
        labels.append(bytes([len(part_b)]) + part_b)
    qname = b"".join(labels) + b"\x00"
    qtype_qclass = b"\x00\x01\x00\x01"
    return header + qname + qtype_qclass


def test_dns_listener_observes_token():
    listener = DnsCallbackListener(host="127.0.0.1", port=0)
    listener.start()
    try:
        token = "stealthixtoken"
        query_name = f"{token}.example.com"
        packet = _dns_query(query_name)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            sock.sendto(packet, ("127.0.0.1", listener.bound_port))
            sock.recvfrom(4096)
        finally:
            sock.close()
        assert listener.wait_for_token(token, timeout=1.0) is True
    finally:
        listener.stop()


def test_dns_listener_defaults_to_loopback():
    assert DnsCallbackListener().host == "127.0.0.1"


def test_dns_listener_query_log_and_multi_token_wait():
    listener = DnsCallbackListener(host="127.0.0.1", port=0)
    listener.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            for name in ["alpha.example.com", "beta.example.com"]:
                sock.sendto(_dns_query(name), ("127.0.0.1", listener.bound_port))
                sock.recvfrom(4096)
        finally:
            sock.close()

        assert listener.wait_for_tokens(["alpha", "beta"], timeout=1.0) == {
            "alpha": True,
            "beta": True,
        }
        assert [entry["qname"] for entry in listener.query_log(suffix="example.com")] == [
            "alpha.example.com",
            "beta.example.com",
        ]
        listener.clear()
        assert listener.seen_queries() == []
    finally:
        listener.stop()
