-- Security Agents — PostgreSQL Schema
-- Tables required by sentinel.py, adversary.py, and cie.py

CREATE TABLE IF NOT EXISTS security_findings (
    id BIGSERIAL PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE,
    agent TEXT NOT NULL,  -- 'sentinel' | 'adversary' | 'cie'
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category TEXT NOT NULL,
    technique TEXT,  -- MITRE ATT&CK technique ID
    title TEXT NOT NULL,
    description TEXT,
    evidence JSONB,
    affected_asset TEXT,
    heuristic_source TEXT,  -- 'paloalto' | 'verizon_dbir' | 'mitre' | 'custom'
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'mitigated', 'accepted_risk', 'false_positive')),
    remediation TEXT,
    cvss_score NUMERIC(3,1),
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attack_surface (
    id BIGSERIAL PRIMARY KEY,
    asset_type TEXT NOT NULL,
    asset_id TEXT NOT NULL UNIQUE,
    details JSONB,
    risk_score NUMERIC(3,2),
    last_scanned TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_metrics (
    id BIGSERIAL PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value NUMERIC,
    dimensions JSONB,
    recorded_at TIMESTAMPTZ DEFAULT now()
);

-- CIE tables

CREATE TABLE IF NOT EXISTS improvement_proposals (
    id BIGSERIAL PRIMARY KEY,
    proposal_id TEXT NOT NULL UNIQUE,
    source_type TEXT,
    source_ref TEXT,
    title TEXT NOT NULL,
    improvement_type TEXT,
    description TEXT,
    estimated_impact NUMERIC(3,2),
    validation_status TEXT DEFAULT 'pending',
    deployment_status TEXT DEFAULT 'proposed',
    outcome_delta JSONB,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS research_ingestion (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT,
    summary TEXT,
    techniques_extracted JSONB,
    applicability_score NUMERIC(3,2),
    applied BOOLEAN DEFAULT false,
    ingested_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS improvement_history (
    id BIGSERIAL PRIMARY KEY,
    proposal_id TEXT REFERENCES improvement_proposals(proposal_id),
    agent_name TEXT,
    metric_name TEXT,
    value_before NUMERIC,
    value_after NUMERIC,
    delta NUMERIC,
    measured_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON security_findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_agent ON security_findings(agent);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON security_findings(last_seen);
CREATE INDEX IF NOT EXISTS idx_attack_surface_type ON attack_surface(asset_type);
CREATE INDEX IF NOT EXISTS idx_proposals_status ON improvement_proposals(validation_status);
CREATE INDEX IF NOT EXISTS idx_research_source ON research_ingestion(source);
