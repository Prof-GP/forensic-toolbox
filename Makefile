.PHONY: help install install-dev install-all venv clean test lint format build upload dist check

VENV := venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
BLACK := $(VENV)/bin/black
FLAKE8 := $(VENV)/bin/flake8

help:
	@echo "Forensic Toolbox - Makefile Commands"
	@echo "====================================="
	@echo "  make venv           - Create virtual environment"
	@echo "  make install        - Install package in venv"
	@echo "  make install-dev    - Install with development dependencies"
	@echo "  make install-all    - Install with all optional dependencies"
	@echo "  make test           - Run tests"
	@echo "  make lint           - Run code linting"
	@echo "  make format         - Format code with black"
	@echo "  make check          - Run lint and tests"
	@echo "  make build          - Build distribution packages"
	@echo "  make upload         - Upload to PyPI"
	@echo "  make clean          - Remove build artifacts and venv"
	@echo "  make dist           - Create distributable package"

venv:
	@echo "Creating virtual environment..."
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel
	@echo "Virtual environment created at ./$(VENV)"
	@echo "Activate with: source $(VENV)/bin/activate (Linux/Mac)"
	@echo "            or: $(VENV)\\Scripts\\activate (Windows)"

install: venv
	@echo "Installing forensic-toolbox..."
	$(PIP) install -e .
	@echo ""
	@echo "Installation complete!"
	@echo "Run with: $(VENV)/bin/forensic-toolbox <file>"
	@echo "      or: $(VENV)/bin/ftb <file>"

install-dev: venv
	@echo "Installing forensic-toolbox with development dependencies..."
	$(PIP) install -e ".[dev]"
	@echo "Development installation complete!"

install-all: venv
	@echo "Installing forensic-toolbox with all optional dependencies..."
	$(PIP) install -e ".[all]"
	@echo "Full installation complete!"

test: venv
	@echo "Running tests..."
	$(PYTEST) tests/ -v

lint: venv
	@echo "Running linting..."
	$(FLAKE8) Toolbox/ main.py --max-line-length=100 --exclude=$(VENV)

format: venv
	@echo "Formatting code..."
	$(BLACK) Toolbox/ main.py

check: lint test
	@echo "All checks passed!"

build: clean
	@echo "Building distribution packages..."
	$(PYTHON) -m pip install --upgrade build
	$(PYTHON) -m build
	@echo "Build complete! Packages in dist/"

upload: build
	@echo "Uploading to PyPI..."
	$(PYTHON) -m pip install --upgrade twine
	$(PYTHON) -m twine upload dist/*

dist: build
	@echo "Creating distributable archive..."
	@mkdir -p release
	@cp dist/* release/
	@echo "Distribution packages available in release/"

clean:
	@echo "Cleaning up..."
	rm -rf $(VENV)
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf release/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "Cleanup complete!"

# Windows-specific targets
venv-windows:
	@echo "Creating virtual environment (Windows)..."
	python -m venv $(VENV)
	$(VENV)\Scripts\pip install --upgrade pip setuptools wheel
	@echo "Virtual environment created!"
	@echo "Activate with: $(VENV)\Scripts\activate"

install-windows: venv-windows
	@echo "Installing forensic-toolbox (Windows)..."
	$(VENV)\Scripts\pip install -e .
	@echo "Installation complete!"
	@echo "Run with: $(VENV)\Scripts\forensic-toolbox <file>"