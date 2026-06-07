"""
Active-scan authorization guard.

Active scanning (port scans, service/version probes, web vuln scans) is only
ever performed against targets the operator is authorised to test. This module
enforces that with a DEFAULT-DENY allowlist:

  * Nothing is scannable until it is explicitly authorised via authorize_target()
    with an attestation string (the operator affirming they own / are authorised
    to test the target) and an authorising identity.
  * Authorisations are persisted (so they survive process restarts) and audited.
  * is_authorized() matches a host or IP against authorised hostnames and CIDRs,
    resolving hostnames to IPs and checking both.

This is the control that separates a legitimate security tool from abuse.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..config import PATHS

# scanme.nmap.org is the host Nmap explicitly provides for scan testing — the
# only target pre-authorised here, as a safe out-of-the-box demo. Everything
# else must be authorised by the operator.
PREAUTHORISED_HOSTS = {"scanme.nmap.org", "localhost", "127.0.0.1"}


@dataclass
class Authorization:
    target: str
    kind: str          # "host" | "cidr" | "ip"
    attestation: str
    authorized_by: str
    authorized_at_utc: str


class AuthorizationStore:
    def __init__(self, path: Path | None = None):
        self.path = path or (PATHS.root / ".scan_authorization.json")
        self._lock = threading.Lock()
        self._auths: dict[str, Authorization] = {}
        self._load()
        for h in PREAUTHORISED_HOSTS:
            self._auths.setdefault(h, Authorization(
                target=h, kind="host", attestation="built-in safe test target",
                authorized_by="syber", authorized_at_utc=_now()))

    def _load(self) -> None:
        if self.path.is_file():
            try:
                for rec in json.loads(self.path.read_text()):
                    self._auths[rec["target"]] = Authorization(**rec)
            except (json.JSONDecodeError, TypeError, KeyError):
                pass

    def _persist(self) -> None:
        self.path.write_text(json.dumps(
            [asdict(a) for a in self._auths.values() if a.authorized_by != "syber"], indent=2))

    def authorize(self, target: str, attestation: str, authorized_by: str) -> Authorization:
        if not attestation or len(attestation.strip()) < 8:
            raise ValueError("attestation required: affirm you own / are authorised to test this target")
        kind = _classify(target)
        auth = Authorization(target=target.strip(), kind=kind, attestation=attestation.strip(),
                             authorized_by=authorized_by or "operator", authorized_at_utc=_now())
        with self._lock:
            self._auths[auth.target] = auth
            self._persist()
        from ..audit.log import get_audit_log
        get_audit_log().write("scan_authorization", {"target": auth.target, "kind": kind,
                                                     "authorized_by": auth.authorized_by}, "scan_guard")
        return auth

    def list(self) -> list[Authorization]:
        return list(self._auths.values())

    def is_authorized(self, target: str) -> tuple[bool, str]:
        """Return (allowed, reason). Resolves hostnames and checks IPs/CIDRs."""
        target = target.strip()
        if target in self._auths:
            return True, f"explicitly authorised ({self._auths[target].kind})"

        # Resolve to IP(s) and test against authorised IPs and CIDRs.
        candidate_ips: set[str] = set()
        try:
            ipaddress.ip_address(target)
            candidate_ips.add(target)
        except ValueError:
            try:
                candidate_ips = {i[4][0] for i in socket.getaddrinfo(target, None)}
            except socket.gaierror:
                candidate_ips = set()

        for auth in self._auths.values():
            if auth.kind == "cidr":
                net = ipaddress.ip_network(auth.target, strict=False)
                for ip in candidate_ips:
                    try:
                        if ipaddress.ip_address(ip) in net:
                            return True, f"within authorised CIDR {auth.target}"
                    except ValueError:
                        continue
            elif auth.kind in ("ip", "host"):
                # host authorisation also covers its resolved IPs
                try:
                    host_ips = {i[4][0] for i in socket.getaddrinfo(auth.target, None)}
                except socket.gaierror:
                    host_ips = {auth.target}
                if candidate_ips & host_ips:
                    return True, f"resolves to authorised target {auth.target}"
        return False, "NOT AUTHORISED — authorise it first via syber_authorize_target"


def _classify(target: str) -> str:
    try:
        ipaddress.ip_network(target, strict=False)
        return "cidr" if "/" in target else "ip"
    except ValueError:
        return "host"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_store: AuthorizationStore | None = None


def get_auth_store() -> AuthorizationStore:
    global _store
    if _store is None:
        _store = AuthorizationStore()
    return _store
