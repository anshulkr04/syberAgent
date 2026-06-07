// Neo4j node/edge schema + RBAC (spec §6.1 / §6.3).

// --- Node labels ----------------------------------------------------------
// (:Asset {id, hostname, ip, asset_class, criticality, os, patch_level})
// (:Identity {id, principal_name, identity_type, department, mfa_enabled, last_seen})
// (:Vulnerability {cve_id, cvss_base, cvss_exploitability, patch_available, first_seen})
// (:CloudResource {id, provider, type, region, public_facing, misconfigured})
// (:NetworkSegment {id, name, zone_type, internet_facing})

// --- Constraints ----------------------------------------------------------
CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT identity_id IF NOT EXISTS FOR (i:Identity) REQUIRE i.id IS UNIQUE;
CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;

// --- Edge types -----------------------------------------------------------
// (:Asset)-[:REACHABLE_FROM {protocol, port, authenticated_required}]->(:Asset)
// (:Identity)-[:HAS_ACCESS {permission_level, method, last_used}]->(:Asset)
// (:Asset)-[:HAS_VULN {exploitability_score, weaponised}]->(:Vulnerability)
// (:Identity)-[:TRUSTS {trust_type, scope}]->(:Identity)
// (:Asset)-[:BELONGS_TO]->(:NetworkSegment)

// --- Fine-grained RBAC (Neo4j Enterprise, spec §6.3) ----------------------
CREATE ROLE llm_investigator_role;
GRANT READ {*}   ON GRAPH syber TO llm_investigator_role;
GRANT TRAVERSE   ON GRAPH syber TO llm_investigator_role;

CREATE ROLE graph_agent_role;
GRANT ALL GRAPH PRIVILEGES ON GRAPH syber TO graph_agent_role;
