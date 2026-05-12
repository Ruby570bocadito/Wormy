.PHONY: setup attack cleanup test lint typecheck install dev

# ── Installation ──────────────────────────────────────────────────────────

install:
	pip install -e ".[dev]"

dev:
	pip install -e ".[dev]"

# ── Docker Lab ────────────────────────────────────────────────────────────

setup:
	@echo "Starting vulnerable Docker lab..."
	docker compose -f docker-compose-lab.yml up -d
	@echo "Lab active. Check IPs with 'docker ps'."

attack:
	@echo "Starting Wormy C2 and propagation (interactive CLI)..."
	python3 worm_core.py --interactive

cleanup:
	@echo "Stopping Docker lab..."
	docker compose -f docker-compose-lab.yml down
	@echo "Environment cleaned."

# ── Testing ───────────────────────────────────────────────────────────────

test:
	python3 -m pytest tests/ -v --tb=short

test-cov:
	python3 -m pytest tests/ --cov --cov-report=term-missing -v

# ── Code Quality ──────────────────────────────────────────────────────────

lint:
	black --check .
	isort --check-only .
	flake8 --max-line-length=100 --exclude=.git,__pycache__,build,dist

format:
	black .
	isort .

typecheck:
	mypy worm_core.py cli.py --ignore-missing-imports

# ── Enterprise (simulated) ────────────────────────────────────────────────

enterprise-dry:
	sudo bash scripts/deploy_kali.sh --dry-run

# ── Help ──────────────────────────────────────────────────────────────────

help:
	@echo "Wormy v4.0 Makefile"
	@echo ""
	@echo "  make install     — Install package in dev mode"
	@echo "  make setup       — Start Docker vulnerable lab"
	@echo "  make attack      — Run interactive CLI"
	@echo "  make test        — Run tests"
	@echo "  make lint        — Check code style"
	@echo "  make format      — Auto-format code"
	@echo "  make cleanup     — Stop Docker lab"
