-- Core org table — one row per organisation (grouped from raw scan IPs)
CREATE TABLE IF NOT EXISTS orgs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT    UNIQUE NOT NULL,
    isp                  TEXT    DEFAULT '',
    countries            TEXT    DEFAULT '[]',   -- JSON array of country names
    total_ips            INTEGER DEFAULT 0,
    total_records        INTEGER DEFAULT 0,
    exposed_ports        TEXT    DEFAULT '[]',   -- JSON array of ints
    risky_ports          TEXT    DEFAULT '[]',   -- JSON array — subset of exposed that are high-risk
    products             TEXT    DEFAULT '[]',   -- JSON array of detected software names
    tech_stack           TEXT    DEFAULT '{}',   -- JSON {tech: [categories]}
    cpe23_list           TEXT    DEFAULT '[]',   -- JSON array of CPE 2.3 strings
    domains              TEXT    DEFAULT '[]',   -- JSON array of linked domains
    -- Risk flags (all derived from tags / port analysis)
    has_vulns            INTEGER DEFAULT 0,      -- 1 = Shodan found CVEs
    vuln_ids             TEXT    DEFAULT '[]',   -- JSON array of CVE IDs
    has_eol_product      INTEGER DEFAULT 0,      -- running end-of-life software
    has_self_signed      INTEGER DEFAULT 0,      -- self-signed TLS certs
    has_iot              INTEGER DEFAULT 0,      -- IoT devices exposed
    has_vpn              INTEGER DEFAULT 0,      -- VPN infrastructure visible
    has_honeypot         INTEGER DEFAULT 0,      -- honeypot activity detected
    has_risky_port       INTEGER DEFAULT 0,      -- any RISKY_PORTS match
    http_200_count       INTEGER DEFAULT 0,      -- open (unauthenticated) HTTP services
    http_auth_count      INTEGER DEFAULT 0,      -- 401/407 — auth present but still exposed
    -- Computed
    attack_surface_score REAL    DEFAULT 0.0,    -- 0–100, higher = more urgent prospect
    signals              TEXT    DEFAULT '{}',   -- JSON {signal_key: {label, weight, ...}}
    last_seen            TEXT,                   -- ISO timestamp of most recent scan record
    created_at           TEXT    DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_orgs_score        ON orgs(attack_surface_score DESC);
CREATE INDEX IF NOT EXISTS idx_orgs_name         ON orgs(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_orgs_eol          ON orgs(has_eol_product);
CREATE INDEX IF NOT EXISTS idx_orgs_self_signed  ON orgs(has_self_signed);
CREATE INDEX IF NOT EXISTS idx_orgs_iot          ON orgs(has_iot);
CREATE INDEX IF NOT EXISTS idx_orgs_vulns        ON orgs(has_vulns);
CREATE INDEX IF NOT EXISTS idx_orgs_risky_port   ON orgs(has_risky_port);

-- LLM output cache — avoids re-generating summaries / outreach on every page load
CREATE TABLE IF NOT EXISTS llm_cache (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    org_name       TEXT    NOT NULL,
    task           TEXT    NOT NULL,   -- 'summary' | 'outreach'
    prompt_version INTEGER NOT NULL,
    model          TEXT    NOT NULL,
    output         TEXT    NOT NULL,
    input_tokens   INTEGER DEFAULT 0,
    output_tokens  INTEGER DEFAULT 0,
    cost_usd       REAL    DEFAULT 0,
    created_at     TEXT    DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_name, task, prompt_version)
);
