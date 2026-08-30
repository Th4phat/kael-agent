.PHONY: help install setup-dev format fix lint type-check security check test \
	test-unit test-integration test-network test-cov package-check sandbox-build \
	pre-commit clean

help:
	@echo "Setup:"
	@echo "  install          Install locked runtime dependencies"
	@echo "  setup-dev        Install locked development dependencies and hooks"
	@echo ""
	@echo "Validation and packaging:"
	@echo "  check            Run the local source-release gate"
	@echo "  lint             Check Ruff formatting and lint"
	@echo "  type-check       Run the incremental strict mypy gate"
	@echo "  security         Run medium/high-confidence Bandit checks"
	@echo "  package-check    Build wheel and sdist"
	@echo ""
	@echo "Tests:"
	@echo "  test-unit        Offline unit suite"
	@echo "  test-integration Container-runtime-dependent suite"
	@echo "  test-network     Live external-service suite"
	@echo "  test-cov         Offline coverage report"
	@echo ""
	@echo "Mutating developer helpers:"
	@echo "  format           Rewrite Python formatting"
	@echo "  fix              Apply safe Ruff fixes"
	@echo "  sandbox-build    Build the versioned local sandbox"

install:
	uv sync --frozen --no-dev

setup-dev:
	uv sync --frozen
	uv run pre-commit install

format:
	uv run ruff format kael tests

fix:
	uv run ruff check kael tests --fix

lint:
	uv run ruff format --check kael tests
	uv run ruff check kael tests

type-check:
	uv run mypy kael

security:
	uv run bandit -r kael -c pyproject.toml -q -ll -ii

test: test-unit

test-unit:
	uv run pytest tests -m "not integration and not network" --timeout=60

test-integration:
	uv run pytest tests -m integration --timeout=300

test-network:
	uv run pytest tests -m network --timeout=180

test-cov:
	uv run pytest tests -m "not integration and not network" --timeout=60 \
		--cov=kael --cov-report=term-missing --cov-report=html --cov-fail-under=45

package-check:
	uv build

check:
	uv lock --check
	$(MAKE) lint
	$(MAKE) type-check
	$(MAKE) security
	$(MAKE) test-unit
	$(MAKE) package-check

sandbox-build:
	uv run kael sandbox build

pre-commit:
	uv run pre-commit run --all-files

clean:
	find kael tests -type d -name "__pycache__" -prune -exec rm -rf {} +
	find kael tests -name "*.pyc" -delete
	rm -rf build dist htmlcov coverage.xml
