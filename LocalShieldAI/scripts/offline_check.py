"""Offline proof: block every non-local network connection, then run real checks.

    python -m scripts.offline_check

Any attempt to reach something other than this computer (127.0.0.1 / localhost) is
BLOCKED and listed. The check passes only if there were zero attempts and every
analysis still returned a result. It covers our analysis code (URL and SMS detectors,
the link checks and the Llama adapter). The Streamlit server and pip are separate:
see the manual check in the README (turn Wi-Fi off, start the app, use it)."""
import ipaddress
import socket

attempts = []
_connect, _getaddrinfo = socket.socket.connect, socket.getaddrinfo


def _is_local(host) -> bool:
    if host in ("localhost", "", None):
        return True
    try:
        return ipaddress.ip_address(str(host)).is_loopback
    except ValueError:
        return False


def _guard_connect(self, address):
    host = address[0] if isinstance(address, tuple) else address
    if not _is_local(host):
        attempts.append(f"connect {address}")
        raise OSError(f"Blocked by offline check: {address}")
    return _connect(self, address)


def _guard_getaddrinfo(host, *args, **kwargs):
    if not _is_local(host):
        attempts.append(f"dns lookup {host}")
        raise socket.gaierror(f"Blocked by offline check: {host}")
    return _getaddrinfo(host, *args, **kwargs)


socket.socket.connect = _guard_connect
socket.getaddrinfo = _guard_getaddrinfo

from services.analysis_service import AnalysisService  # noqa: E402  (after the guard on purpose)

URLS = ["https://www.google.com/", "http://paytm-kyc-update.xyz/login", "gooogle.cooom",
        "http://192.168.1.5/login", "https://example.com/a?next=http://evil.test"]
SMS = ["URGENT! Your account is blocked. Verify KYC now at http://bit.ly/x9 or lose access",
       "HDFC Bank: verify your account at http://hdfc-kyc-update.xyz/login",
       "Your verification code is 482731. Do not share this code with anyone.",
       "see you at lunch tomorrow"]


def main():
    service = AnalysisService()
    failures, done = [], 0
    for kind, items in (("url", URLS), ("sms", SMS)):
        for text in items:
            r = service.analyze(text, forced=kind, use_llm=True)  # Llama may fall back: fine
            if not r["ok"]:
                failures.append(f"{kind}: {text[:50]} -> {r['message']}")
                continue
            done += 1
            print(f"{kind.upper():3s} {r['detection']['risk_level']:12s} "
                  f"explained_by={r['explanation']['source']:17s} {text[:55]}")
    print()
    print(f"Analyses completed: {done}   Failed: {len(failures)}")
    print(f"Outside connection attempts blocked: {len(attempts)}")
    for a in sorted(set(attempts)):
        print("   -", a)
    for f in failures:
        print("   FAILED:", f)
    ok = not attempts and not failures
    print("\nOFFLINE CHECK", "PASSED" if ok else "FAILED")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()