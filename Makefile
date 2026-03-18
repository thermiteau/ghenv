.PHONY: test lint typecheck check build install sync clean

## Testing & Quality

test: ## Run all tests
	uv run pytest tests/test_ghenv_lib.py -v

test-cov: ## Run tests with coverage report
	uv run pytest --cov=ghenv --cov-report=html

lint: ## Run ruff linter
	uv run ruff check .

lint-fix: ## Run ruff linter with auto-fix
	uv run ruff check --fix .

format: ## Run ruff formatter
	uv run ruff format .

format-check: ## Check formatting without applying changes
	uv run ruff format --check .

typecheck: ## Run pyright type checker
	uv run pyright

check: lint typecheck test ## Run all quality checks (lint, typecheck, test)

## Build & Install

build: ## Build the package
	uv build

install: ## Install the package in editable mode
	uv pip install -e .

sync: ## Sync all dependencies (including test and dev)
	uv sync --all-extras

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache htmlcov .coverage

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
