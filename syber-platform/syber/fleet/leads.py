"""
Lead registry + evidence ladder (fleet Phase 8) — verify, don't just discover.

The failure this fixes: the fleet found an exposed Keycloak admin console and
declared the engagement COMPLETE at "MEDIUM — no confirmed exploit," because its
done-condition was a *coverage fixpoint* and ``found_something()`` returned True on
ANY vuln. A real analyst treats a discovery as a **hypothesis to verify** and keeps
climbing an evidence ladder until it confirms impact or genuinely exhausts every
avenue.

This module is the control logic for that (research_verify.md):

  * **Evidence ladder** (rung 0..5): severity is *earned by demonstrated evidence*,
    not by how scary the surface looks. Reachable = INFO; version-matches-CVE =
    LOW/hypothesis; verified-exploit = HIGH; demonstrated-impact = CRITICAL. A
    matched CVE's headline score is only the *ceiling* until preconditions are proven
    (CVSS v4 user guide; bug-bounty triage: "no PoC -> Informational").
  * **Lead taxonomy**: every discovery is classified; HIGH-VALUE classes (exposed
    admin, version-matched CVE, exposed secret, default-cred-able, auth-bypass /
    injection / unauth-datastore candidates) MUST reach VERIFIED or EXHAUSTED before
    the engagement may end.
  * **Done predicate**: ``no_open_highvalue_lead()`` — the engagement cannot finish
    while a high-value lead is unverified. EXHAUSTED requires a *logged failed
    attempt per hypothesis* (not "didn't try"), so the agent can't quietly give up.

Pure data + classification over the attack graph; no network, unit-tested. The
verification *runners* (verify_runners.py) climb the ladder; the coordinator's
done-condition (Phase 8c) consults this registry.

Refs: research_verify.md — Fang 2404.08144 (CVE-desc = 87% vs 7%), PentestGPT PTT
2308.06782, AutoPenBench 2410.03225 (21% vs 64% autonomy gap), Anthropic
long-running-agent harness, CVSS v4, HackerOne/Bugcrowd triage, PTES/WSTG.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any

__all__ = ["EvidenceRung", "LeadClass", "LeadState", "HIGH_VALUE_CLASSES",
           "Hypothesis", "Lead", "LeadRegistry", "severity_for_rung",
           "classify_node", "verify_task_kinds_for"]


# --------------------------------------------------------------------------- #
# Evidence ladder
# --------------------------------------------------------------------------- #
class EvidenceRung(IntEnum):
    """Severity is the highest rung with concrete evidence (research_verify §2.2)."""
    INFORMATIONAL = 0   # surface reachable (banner / endpoint / version string)
    HYPOTHESIS = 1      # exact version matches a known CVE (UNCONFIRMED)
    PRECONDITION = 2    # the vulnerable code path is reachable (low-priv acct / endpoint responds)
    VERIFIED = 3        # reproducible PoC — the security boundary was broken (HIGH)
    IMPACT = 4          # demonstrated material harm — dumped data / token / RCE / pivot (CRITICAL)
    CHAINED = 5         # multiple verified vulns combined


# Map a rung to the platform severity vocabulary (scoring/severity.SEVERITY_ORDER).
_RUNG_SEVERITY = {
    EvidenceRung.INFORMATIONAL: "INFO",
    EvidenceRung.HYPOTHESIS: "LOW",
    EvidenceRung.PRECONDITION: "MEDIUM",
    EvidenceRung.VERIFIED: "HIGH",
    EvidenceRung.IMPACT: "CRITICAL",
    EvidenceRung.CHAINED: "CRITICAL",
}


def severity_for_rung(rung: EvidenceRung | int) -> str:
    return _RUNG_SEVERITY.get(EvidenceRung(int(rung)), "INFO")


# --------------------------------------------------------------------------- #
# Lead taxonomy
# --------------------------------------------------------------------------- #
class LeadClass(str, Enum):
    EXPOSED_ADMIN = "exposed_admin"            # admin/console/management UI reachable
    DEFAULT_CRED_SERVICE = "default_cred"      # service that ships known default creds
    VERSION_CVE = "version_cve"                # product+version matches a known CVE
    EXPOSED_SECRET = "exposed_secret"          # .git / .env / backup / token / key
    AUTH_BYPASS = "auth_bypass"                # 401/403 path with a bypass candidate
    INJECTION = "injection"                    # XSS / SQLi / SSRF / IDOR candidate
    DATASTORE_UNAUTH = "datastore_unauth"      # Redis/Mongo/ES/Docker/K8s open access
    UNAUTH_STATE_CHANGE = "unauth_state_change"  # self-registration / unauth write endpoint
    UNAUTH_API_DATA = "unauth_api_data"        # reachable API/data endpoint — verify real data
    LOW_VALUE = "low_value"                    # missing headers, verbose errors, cosmetic

    def __str__(self) -> str:
        return self.value


# Classes that MUST be verified (or exhausted) before the engagement can end.
HIGH_VALUE_CLASSES = frozenset({
    LeadClass.EXPOSED_ADMIN, LeadClass.DEFAULT_CRED_SERVICE, LeadClass.VERSION_CVE,
    LeadClass.EXPOSED_SECRET, LeadClass.AUTH_BYPASS, LeadClass.INJECTION,
    LeadClass.DATASTORE_UNAUTH, LeadClass.UNAUTH_STATE_CHANGE,
    LeadClass.UNAUTH_API_DATA,
})


class LeadState(str, Enum):
    OPEN = "open"              # discovered, not yet worked
    VERIFYING = "verifying"    # verification in progress
    VERIFIED = "verified"      # reached rung >= VERIFIED with evidence
    EXHAUSTED = "exhausted"    # every hypothesis tried and logged-failed

    def __str__(self) -> str:
        return self.value


# Which verification task kinds apply to each lead class (drives frontier spawning).
_CLASS_VERIFY_KINDS = {
    LeadClass.EXPOSED_ADMIN: ["service_probe", "default_login_check", "cve_lookup"],
    LeadClass.DEFAULT_CRED_SERVICE: ["default_login_check"],
    LeadClass.VERSION_CVE: ["cve_lookup", "cve_verify"],
    LeadClass.EXPOSED_SECRET: ["exposed_artifact_check", "data_extraction"],
    LeadClass.AUTH_BYPASS: ["http_verb_tampering"],
    LeadClass.INJECTION: ["test_injection", "test_access_control"],
    LeadClass.DATASTORE_UNAUTH: ["datastore_unauth_probe"],
    LeadClass.UNAUTH_STATE_CHANGE: ["service_probe", "data_extraction"],
    LeadClass.UNAUTH_API_DATA: ["data_extraction"],
    LeadClass.LOW_VALUE: [],
}


def verify_task_kinds_for(lead_class: LeadClass) -> list[str]:
    return list(_CLASS_VERIFY_KINDS.get(lead_class, []))


# --------------------------------------------------------------------------- #
# Lead + hypothesis records
# --------------------------------------------------------------------------- #
@dataclass
class Hypothesis:
    id: str
    description: str
    verify_kind: str                 # the verification task kind that tests it
    attempts: int = 0
    failed: bool = False             # a logged failed attempt (required for EXHAUSTED)
    note: str = ""                   # reflection / why it failed (Reflexion)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "description": self.description, "verify_kind": self.verify_kind,
                "attempts": self.attempts, "failed": self.failed, "note": self.note}


@dataclass
class Lead:
    id: str
    lead_class: LeadClass
    target: str                      # graph node id / host / url
    product: str = ""
    version: str = ""
    rung: EvidenceRung = EvidenceRung.INFORMATIONAL
    state: LeadState = LeadState.OPEN
    hypotheses: list[Hypothesis] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)   # evidence_refs justifying the rung
    reflections: list[str] = field(default_factory=list)

    @property
    def high_value(self) -> bool:
        return self.lead_class in HIGH_VALUE_CLASSES

    @property
    def severity(self) -> str:
        return severity_for_rung(self.rung)

    def add_evidence(self, ref: str, rung: EvidenceRung) -> None:
        """Climb the ladder: record evidence and raise the rung if this is higher.
        Severity only ever rises with demonstrated evidence (never claimed blind)."""
        if ref and ref not in self.evidence:
            self.evidence.append(ref)
        if int(rung) > int(self.rung):
            self.rung = EvidenceRung(int(rung))
        if self.rung >= EvidenceRung.VERIFIED:
            self.state = LeadState.VERIFIED

    def all_hypotheses_failed(self) -> bool:
        return bool(self.hypotheses) and all(h.failed for h in self.hypotheses)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "class": str(self.lead_class), "target": self.target,
                "product": self.product, "version": self.version, "rung": int(self.rung),
                "rung_name": self.rung.name, "severity": self.severity,
                "state": str(self.state), "high_value": self.high_value,
                "hypotheses": [h.to_dict() for h in self.hypotheses],
                "evidence": list(self.evidence), "reflections": list(self.reflections)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Lead":
        lead = cls(id=d["id"], lead_class=LeadClass(d.get("class", "low_value")),
                   target=d.get("target", ""), product=d.get("product", ""),
                   version=d.get("version", ""),
                   rung=EvidenceRung(int(d.get("rung", 0))),
                   state=LeadState(d.get("state", "open")),
                   evidence=list(d.get("evidence", [])),
                   reflections=list(d.get("reflections", [])))
        lead.hypotheses = [Hypothesis(**h) for h in d.get("hypotheses", [])]
        return lead


# --------------------------------------------------------------------------- #
# Classification — turn a graph node into a Lead (idempotent, deterministic id)
# --------------------------------------------------------------------------- #
# URL/path patterns that signal an exposed admin/management surface.
_ADMIN_RX = re.compile(
    r"/(?:admin|administrator|manage(?:ment)?|console|dashboard|wp-admin|"
    r"actuator|jenkins|grafana|kibana|phpmyadmin|adminer|portainer|rancher|"
    r"auth/admin|realms/master|api/v\d+/admin)\b", re.IGNORECASE)
# Secret / source exposure patterns.
_SECRET_RX = re.compile(
    r"/(?:\.git(?:/|$)|\.env(?:$|\.)|\.svn|\.aws|web\.config|"
    r"backup|\.bak$|id_rsa|credentials|secrets?\.(?:ya?ml|json|txt))", re.IGNORECASE)
# Products that ship known default credentials / are high-value when exposed.
_DEFAULT_CRED_PRODUCTS = re.compile(
    r"keycloak|jenkins|grafana|tomcat|gitlab|jboss|wildfly|weblogic|"
    r"phpmyadmin|kibana|rabbitmq|airflow|superset|nexus|sonarqube", re.IGNORECASE)
# Datastores that are critical when reachable without auth.
_DATASTORE_RX = re.compile(r"redis|mongo|elastic|memcached|cassandra|docker|kubelet|kubernetes", re.IGNORECASE)
_DATASTORE_PORTS = {6379, 27017, 9200, 9300, 11211, 5601, 2375, 2376, 10250, 6443}
# API documentation / spec exposure — leaks the whole surface (Swagger/OpenAPI/GraphQL).
_APIDOC_RX = re.compile(
    r"/(?:swagger(?:-ui)?|api-?docs?|openapi(?:\.json|\.ya?ml)?|v\d+/api-docs|"
    r"graphql|graphiql|redoc|api/explorer)\b", re.IGNORECASE)
# Data/API endpoints — reachable ones are leads to verify by pulling a real sample.
_API_RX = re.compile(r"/(?:api|mwapi|rest|v\d+|graphql|odata|services?|gateway)/", re.IGNORECASE)


def _is_2xx(status: Any) -> bool:
    try:
        return 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def classify_node(node_id: str, props: dict[str, Any]) -> Lead | None:
    """Classify one graph node into a Lead (or None if it isn't lead-worthy yet).
    Pure: deterministic lead id so re-classification is idempotent."""
    label = props.get("label")

    if label == "WebEndpoint":
        url = props.get("url") or node_id
        if _SECRET_RX.search(url) or _APIDOC_RX.search(url):
            return Lead(id=f"lead:secret:{url}", lead_class=LeadClass.EXPOSED_SECRET, target=url)
        if _ADMIN_RX.search(url):
            return Lead(id=f"lead:admin:{url}", lead_class=LeadClass.EXPOSED_ADMIN, target=url)
        # A reachable (2xx) API/data endpoint is a lead to verify by pulling real data —
        # a 200 is rung 2/3; only a confirmed sensitive sample earns IMPACT.
        if _API_RX.search(url) and _is_2xx(props.get("status")):
            return Lead(id=f"lead:apidata:{url}", lead_class=LeadClass.UNAUTH_API_DATA, target=url)
        return None

    if label in ("Technology", "Service"):
        name = (props.get("name") or props.get("product") or "")
        version = props.get("version") or ""
        if not name:
            return None
        target = node_id
        if _DEFAULT_CRED_PRODUCTS.search(name):
            return Lead(id=f"lead:defcred:{target}", lead_class=LeadClass.DEFAULT_CRED_SERVICE,
                        target=target, product=name, version=version)
        port = props.get("port")
        if _DATASTORE_RX.search(name) or (isinstance(port, int) and port in _DATASTORE_PORTS):
            return Lead(id=f"lead:datastore:{target}", lead_class=LeadClass.DATASTORE_UNAUTH,
                        target=target, product=name, version=version)
        if version:   # any product with a pinned version is a CVE-correlation lead
            return Lead(id=f"lead:cve:{target}", lead_class=LeadClass.VERSION_CVE,
                        target=target, product=name, version=version)
        return None

    if label == "Vulnerability":
        # An unconfirmed vuln node (e.g. nuclei template hit) is a CVE lead to verify.
        vid = props.get("id") or node_id
        sev = str(props.get("severity", "")).lower()
        if sev in ("critical", "high", "medium", "unknown", ""):
            return Lead(id=f"lead:vuln:{vid}", lead_class=LeadClass.VERSION_CVE, target=vid,
                        product=str(props.get("name", "")))
    return None


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
class LeadRegistry:
    """Holds the engagement's leads. Derived from the attack graph; persisted in the
    coordinator checkpoint. The done-condition consults ``no_open_highvalue_lead``."""

    def __init__(self) -> None:
        self._leads: dict[str, Lead] = {}

    # -- derivation -------------------------------------------------------- #
    def derive_from_graph(self, graph: Any) -> list[Lead]:
        """Scan the graph and register any newly-discovered leads. Idempotent:
        existing leads (in any state) are left untouched so verification progress and
        EXHAUSTED/VERIFIED decisions are never reset. Returns newly-added leads."""
        added: list[Lead] = []
        try:
            nodes = list(graph.g.nodes(data=True))
        except Exception:  # noqa: BLE001
            return added
        for nid, props in nodes:
            try:
                lead = classify_node(nid, props)
            except Exception:  # noqa: BLE001
                lead = None
            if lead is None:
                continue
            if lead.id not in self._leads:
                self._attach_hypotheses(lead)
                self._leads[lead.id] = lead
                added.append(lead)
        return added

    def _attach_hypotheses(self, lead: Lead) -> None:
        """Seed a lead with the hypotheses a human would test for its class."""
        for kind in verify_task_kinds_for(lead.lead_class):
            lead.hypotheses.append(Hypothesis(
                id=f"{lead.id}:{kind}", description=f"verify via {kind}", verify_kind=kind))

    # -- access ------------------------------------------------------------ #
    def get(self, lead_id: str) -> Lead | None:
        return self._leads.get(lead_id)

    def all(self) -> list[Lead]:
        return list(self._leads.values())

    def add(self, lead: Lead) -> Lead:
        if lead.id not in self._leads:
            if not lead.hypotheses:
                self._attach_hypotheses(lead)
            self._leads[lead.id] = lead
        return self._leads[lead.id]

    def open_highvalue(self) -> list[Lead]:
        return [l for l in self._leads.values()
                if l.high_value and l.state not in (LeadState.VERIFIED, LeadState.EXHAUSTED)]

    def no_open_highvalue_lead(self) -> bool:
        """THE done-gate: True only when every high-value lead is VERIFIED or
        EXHAUSTED. While any remains OPEN/VERIFYING, the engagement is not done."""
        return not self.open_highvalue()

    # -- resolution -------------------------------------------------------- #
    def record_attempt(self, lead_id: str, verify_kind: str, *, success: bool,
                       evidence_ref: str = "", rung: EvidenceRung | None = None,
                       note: str = "") -> Lead | None:
        """Record a verification attempt against a lead's matching hypothesis. On
        success, climb the ladder; on failure, mark the hypothesis failed + reflect.
        When all hypotheses have a logged failure, the lead becomes EXHAUSTED."""
        lead = self._leads.get(lead_id)
        if lead is None:
            return None
        lead.state = LeadState.VERIFYING if lead.state == LeadState.OPEN else lead.state
        hyp = next((h for h in lead.hypotheses if h.verify_kind == verify_kind), None)
        if hyp is None:
            hyp = Hypothesis(id=f"{lead_id}:{verify_kind}", description=f"verify via {verify_kind}",
                             verify_kind=verify_kind)
            lead.hypotheses.append(hyp)
        hyp.attempts += 1
        if note:
            hyp.note = note
        if success:
            lead.add_evidence(evidence_ref, rung if rung is not None else EvidenceRung.VERIFIED)
        else:
            hyp.failed = True
            if note:
                lead.reflections.append(f"[{verify_kind}] {note}")
            if lead.all_hypotheses_failed() and lead.state != LeadState.VERIFIED:
                lead.state = LeadState.EXHAUSTED
        return lead

    def mark_exhausted(self, lead_id: str, note: str = "") -> bool:
        lead = self._leads.get(lead_id)
        if lead is None or lead.state == LeadState.VERIFIED:
            return False
        for h in lead.hypotheses:
            h.failed = True
        lead.state = LeadState.EXHAUSTED
        if note:
            lead.reflections.append(note)
        return True

    def summary(self) -> dict[str, Any]:
        by_state: dict[str, int] = {}
        for l in self._leads.values():
            by_state[str(l.state)] = by_state.get(str(l.state), 0) + 1
        hv = self.open_highvalue()
        return {"total": len(self._leads), "by_state": by_state,
                "open_highvalue": len(hv),
                "open_highvalue_leads": [l.to_dict() for l in hv],
                "verified": [l.to_dict() for l in self._leads.values()
                             if l.state == LeadState.VERIFIED],
                "max_rung": max((int(l.rung) for l in self._leads.values()), default=0)}

    # -- persistence ------------------------------------------------------- #
    def snapshot(self) -> dict[str, Any]:
        return {"leads": [l.to_dict() for l in self._leads.values()]}

    def restore(self, data: dict[str, Any]) -> None:
        self._leads = {d["id"]: Lead.from_dict(d) for d in (data or {}).get("leads", [])}
