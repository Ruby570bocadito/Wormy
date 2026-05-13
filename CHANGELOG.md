# Changelog

## v4.0.0 (2026-05-13)

### Added
- 44 exploit modules (12 new: EternalBlue, Zerologon, PrintNightmare, BlueKeep, WordPress, Apache, CloudFormation, Terraform, GCP IAM, Siemens S7, MQTT, OPC UA)
- worm_core/ package: refactored from 3079-line monolithic into 10 mixin modules
- CI pipeline with lint, security scan, and test jobs
- Pre-commit hooks configuration
- CHANGELOG, CONTRIBUTING, SECURITY.md

### Security
- Fixed shell=True -> shlex.split() in payload_deployer.py
- Fixed exec() -> subprocess.call(shlex.split()) in worm_core.py
- Fixed SQLi f-string -> escaped quotes in enterprise_password_engine.py
- Redacted 13 password leak lines across all exploits
- Replaced 2 bare except: with except Exception: in payload_deployer.py
- Moved 4 hardcoded credentials to env vars (JWT secret, MSF password, SSL verify)
- Added pickle.load() validation guards in scanner and evasion models

### Changed
- All 160 files reformatted with black + isort
- C2 fallback errors demoted from error to warning (normal in standalone mode)
- MultiProtocolC2.stop() added for clean shutdown
- README rewritten with Mermaid diagrams, exploit tables, and detailed architecture
- Requirements.txt synced with pyproject.toml

### Removed
- Junk files: worm_core.py.bak, _test_train.py, _train_output.txt, __pycache__/, .pytest_cache/, logs/, reports/
- Duplicate ML models in worm_core/ml_models/saved/

## v3.0.0 (Previous)

- Initial enterprise release with 32 exploit modules
- RL engine with DQN + Thompson Sampling
- Multi-protocol C2 (HTTPS, DoH, ICMP, cloud relay)
- Enterprise evasion engine (AMSI, ETW, DLL unhooking)
- Active Directory attack chain (LDAP, AS-REP, Kerberoast)
- Web dashboards (Armitage + Web)
