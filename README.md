# Security Agents

Autonomous security agents for AI fleet infrastructure. Three Python agents that continuously monitor, pentest, and improve the security posture of systems running AI agent fleets.

Built and battle-tested on a production fleet of 110 AI agents. Open-sourced by [Monster Gaming](https://monstergaming.ai) / [Luxedeum, LLC](https://luxedeum.ai).

**Blog post:** [We Built AI Agents That Hack Our Own Infrastructure Every 6 Hours](https://blog.monstergaming.ai/we-built-ai-agents-that-hack-our-own-infrastructure-every-6-hours/)

## Agents

### sentinel.py -- Defensive Monitoring

12 heuristic checks derived from real-world threat intelligence:

| Source | Count | What They Check |
|--------|-------|-----------------|
| PAN Unit 42 | 6 | Credential exposure, file permissions, network binding, NATS auth, binary integrity, prompt access |
| Verizon DBIR | 4 | HTTP endpoint auth, DB privilege isolation, error disclosure, detection latency |
| MITRE ATT&CK | 2 | Unexpected ports (T1046), unauthorized systemd services (T1543.002) |

Runs hourly. SIGHUP triggers immediate rescan. HTTP health on configurable port.

### adversary.py -- Offensive Red Team

9 attack playbooks that actually probe your infrastructure:

1. **Reconnaissance** -- port scan + banner grab
2. **Credential harvesting** -- filesystem grep for API keys
3. **Web application attacks** -- SQLi, XSS, path traversal, SSRF, command injection
4. **NATS message injection** -- test message bus authentication
5. **Privilege escalation** -- DB role boundary testing
6. **Prompt injection detection** -- scan LLM response logs for leaks
7. **Lateral movement** -- cross-service access path mapping
8. **Data exfiltration** -- blast radius quantification
9. **DoS resilience** -- spend cap and connection limit headroom

Quick cycle (6h): modules 1-3. Deep cycle (24h): all 9. Safe mode on by default. SIGUSR1 emergency stop.

### cie.py -- Continuous Improvement Engine

Weekly 5-phase meta-improvement cycle:

1. **Measure** -- snapshot fleet metrics and security posture
2. **Research** -- ingest from frontier labs, threat intel, dark web sources
3. **Analyze** -- compare current state to research frontier
4. **Propose** -- generate deployable improvement proposals
5. **Validate** -- shadow test before rollout

Research sources: Anthropic, DeepMind, Meta FAIR, OpenAI, PAN Unit 42, Verizon DBIR, CISA KEV, MITRE ATT&CK, credential breach databases, exploit marketplaces.

## Requirements

- Python 3.10+
- PostgreSQL 14+
- NATS JetStream 2.x (optional, for real-time alerts)
- `psycopg2` (`pip install psycopg2-binary`)

## Setup

```bash
# 1. Create database tables
psql -d yourdb -f schema.sql

# 2. Set environment variables
export DATABASE_URL="postgresql://fleet_svc:password@localhost/yourdb"
export NATS_URL="nats://127.0.0.1:4222"

# 3. Run agents
python3 sentinel.py   # Defensive monitoring on :8776
python3 adversary.py  # Red team on :8777
python3 cie.py        # Improvement engine on :8778
```

## Configuration

All agents are configured via environment variables:

### Sentinel
| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_PORT` | 8776 | HTTP health port |
| `SENTINEL_SCAN_INTERVAL` | 3600 | Seconds between scans |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `NATS_URL` | nats://127.0.0.1:4222 | NATS server URL |

### Adversary
| Variable | Default | Description |
|----------|---------|-------------|
| `ADVERSARY_PORT` | 8777 | HTTP health port |
| `ADVERSARY_QUICK_INTERVAL` | 21600 | Seconds between quick cycles |
| `ADVERSARY_DEEP_INTERVAL` | 86400 | Seconds between deep cycles |
| `ADVERSARY_SAFE_MODE` | true | Enable safety controls |
| `DATABASE_URL` | required | PostgreSQL connection string |

### CIE
| Variable | Default | Description |
|----------|---------|-------------|
| `CIE_PORT` | 8778 | HTTP health port |
| `CIE_CYCLE_INTERVAL` | 604800 | Seconds between improvement cycles |
| `LLM_GATEWAY_URL` | http://127.0.0.1:8760 | LLM gateway for analysis |
| `DATABASE_URL` | required | PostgreSQL connection string |

## systemd

Example service files are in `systemd/`. Install with:

```bash
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel adversary cie
```

## HTTP Endpoints

Each agent exposes health and data endpoints:

**Sentinel** (`:8776`): `/health`, `/findings`, `/metrics`, `/heuristics`
**Adversary** (`:8777`): `/health`, `/attacks`, `/playbook`, `/metrics`
**CIE** (`:8778`): `/health`, `/cycle`, `/proposals`, `/research`, `/sources`

## Customization

**Add heuristics:** Append to the `HEURISTICS` list in sentinel.py with a matching scan function.

**Add attack playbooks:** Add to the `PLAYBOOKS` dict in adversary.py and implement the attack function.

**Add research sources:** Extend `RESEARCH_SOURCES` in cie.py with new URLs and check types.

**Expected ports / known services:** Update `EXPECTED_PORTS` and `KNOWN_SERVICES` in sentinel.py for your infrastructure.

## First Scan Results (Our Production Fleet)

Our first scan against 110 AI agents found 24 findings:

- 6 critical (2 were false positives)
- 6 high
- 8 medium
- 4 info

Key findings: 154 scripts with hardcoded API keys, unauthenticated NATS message injection, unauthenticated state endpoints. All critical and high findings were resolved or mitigated within 24 hours.

See the [blog post](https://blog.monstergaming.ai/we-built-ai-agents-that-hack-our-own-infrastructure-every-6-hours/) for the full breakdown.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome. Security-related contributions (new heuristics, attack modules, research sources) are especially valued.

If you find a vulnerability in these agents themselves, please report it via GitHub Security Advisories rather than a public issue.
