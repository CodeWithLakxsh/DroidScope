# DroidScope developer commands.
#
#   make setup     install backend and frontend dependencies
#   make dev       run the API, worker and frontend together
#   make test      run every test suite
#   make check     lint, type check and test (what CI runs)

SHELL := /bin/bash
.DEFAULT_GOAL := help

BACKEND := backend
FRONTEND := frontend
VENV := $(BACKEND)/.venv
PY := $(VENV)/bin/python
DROIDSCOPE := $(VENV)/bin/droidscope

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- setup ------------------------------------------------------------------
.PHONY: setup
setup: setup-backend setup-frontend ## Install all dependencies

.PHONY: setup-backend
setup-backend: ## Create the virtualenv and install the backend
	@command -v uv >/dev/null || { echo "uv is required: https://docs.astral.sh/uv/"; exit 1; }
	cd $(BACKEND) && uv venv --python 3.12 .venv
	cd $(BACKEND) && uv pip install --python .venv/bin/python -e ".[dev,yara]"
	@echo "Backend ready. Run 'make doctor' to check external tooling."

.PHONY: setup-frontend
setup-frontend: ## Install frontend dependencies
	cd $(FRONTEND) && npm ci

.PHONY: doctor
doctor: ## Report which external analysis tools are available
	$(DROIDSCOPE) doctor

# --- database ---------------------------------------------------------------
.PHONY: db-init
db-init: ## Create the database tables
	$(DROIDSCOPE) init-db

.PHONY: migrate
migrate: ## Apply database migrations
	cd $(BACKEND) && .venv/bin/alembic upgrade head

.PHONY: migration
migration: ## Generate a migration: make migration m="description"
	cd $(BACKEND) && .venv/bin/alembic revision --autogenerate -m "$(m)"

# --- running ----------------------------------------------------------------
.PHONY: api
api: ## Start the API server
	$(DROIDSCOPE) server --reload

.PHONY: worker
worker: ## Start the analysis worker
	$(DROIDSCOPE) worker

.PHONY: web
web: ## Start the frontend dev server
	cd $(FRONTEND) && npm run dev

.PHONY: dev
dev: ## Run API, worker and frontend together
	@echo "API http://127.0.0.1:8000  ·  UI http://localhost:5173  ·  Ctrl-C to stop"
	@trap 'kill 0' EXIT INT TERM; \
	  $(DROIDSCOPE) server & \
	  $(DROIDSCOPE) worker & \
	  (cd $(FRONTEND) && npm run dev) & \
	  wait

# --- fixtures ---------------------------------------------------------------
.PHONY: fixtures
fixtures: ## Build the fixture APKs from source (needs the Android SDK)
	scripts/development/build_fixture_apk.sh all

# --- testing ----------------------------------------------------------------
.PHONY: test
test: test-backend test-frontend ## Run backend and frontend tests

.PHONY: test-backend
test-backend: ## Run backend tests
	cd $(BACKEND) && .venv/bin/pytest -q

.PHONY: test-cov
test-cov: ## Run backend tests with coverage
	cd $(BACKEND) && .venv/bin/pytest --cov=app --cov-report=term-missing --cov-report=html

.PHONY: test-frontend
test-frontend: ## Run frontend unit tests
	cd $(FRONTEND) && npm test

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests (needs a running stack)
	cd $(FRONTEND) && npx playwright test workflow --project=chromium

.PHONY: screenshots
screenshots: ## Recapture documentation screenshots (needs a running stack)
	cd $(FRONTEND) && npx playwright test screenshots --project=chromium

# --- quality ----------------------------------------------------------------
.PHONY: lint
lint: ## Lint the backend and frontend
	cd $(BACKEND) && .venv/bin/ruff check app tests
	cd $(BACKEND) && .venv/bin/ruff format --check app tests
	cd $(FRONTEND) && npm run lint

.PHONY: format
format: ## Format the backend
	cd $(BACKEND) && .venv/bin/ruff check app tests --fix
	cd $(BACKEND) && .venv/bin/ruff format app tests

.PHONY: typecheck
typecheck: ## Type check both projects
	cd $(BACKEND) && .venv/bin/mypy app || true
	cd $(FRONTEND) && npx tsc -b --noEmit

.PHONY: rules
rules: ## Validate every detection rule file
	$(DROIDSCOPE) rules validate

.PHONY: check
check: lint typecheck rules test ## Everything CI runs

.PHONY: build
build: ## Build the production frontend bundle
	cd $(FRONTEND) && npm run build

# --- docker -----------------------------------------------------------------
.PHONY: docker-up
docker-up: ## Start the Docker stack
	docker compose up --build -d
	@echo "DroidScope is at http://localhost:8080"

.PHONY: docker-down
docker-down: ## Stop the Docker stack
	docker compose down

.PHONY: docker-logs
docker-logs: ## Follow Docker logs
	docker compose logs -f

# --- housekeeping -----------------------------------------------------------
.PHONY: clean
clean: ## Remove build output and caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf $(BACKEND)/.pytest_cache $(BACKEND)/.ruff_cache $(BACKEND)/.mypy_cache
	rm -rf $(BACKEND)/htmlcov $(BACKEND)/coverage.xml $(BACKEND)/.coverage
	rm -rf $(FRONTEND)/dist $(FRONTEND)/test-results $(FRONTEND)/playwright-report
