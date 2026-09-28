.DEFAULT_GOAL := help
define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([$$\(\)a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-30s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

.PHONY: help
help:  ## print short description of each target
	@python3 -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

.PHONY: checks
checks: mypy  ## run all the linting checks of the codebase
	uv run pre-commit run --all-files

.PHONY: mypy
mypy:  ## run mypy static type checks
	uv run mypy src

.PHONY: ruff
ruff:  ## fix the code using ruff
	uv run ruff check src tests --fix
	uv run ruff format src tests

.PHONY: test
test:  ## run the tests
	uv run pytest tests -r a -v --cov=src

.PHONY: changelog-draft
changelog-draft:  ## compile a draft of the next changelog
	uv run towncrier build --draft

.PHONY: virtual-environment
virtual-environment:  ## update the virtual environment, creating it if needed
	uv sync --all-extras
	uv run pre-commit install
