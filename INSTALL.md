# Installation Guide - Forensic Toolbox

This guide provides detailed instructions for installing the Forensic Toolbox on various platforms.

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- git (optional, for cloning the repository)

## Quick Installation (Linux/Mac)
```bash
# 1. Clone the repository
git clone https://github.com/Prof-GP/forensic-toolbox.git
cd forensic-toolbox

# 2. Run make install (creates venv and installs everything)
make install

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Test the installation
forensic-toolbox --version
```

## Quick Installation (Windows)
```cmd
# 1. Clone the repository
git clone https://github.com/Prof-GP/forensic-toolbox.git
cd forensic-toolbox

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
venv\Scripts\activate

# 4. Install the package
pip install -e .

# 5. Test the installation
forensic-toolbox --version
```

## Manual Installation (All Platforms)

### Step 1: Download the Project

**Option A: Using Git**
```bash
git clone https://github.com/Prof-GP/forensic-toolbox.git
cd forensic-toolbox
```

**Option B: Download ZIP**
1. Download the ZIP file from GitHub
2. Extract it to a folder
3. Open terminal/command prompt in that folder

### Step 2: Create Virtual Environment

**Linux/Mac:**
```bash
python3 -m venv venv
```

**Windows:**
```cmd
python -m venv venv
```

### Step 3: Activate Virtual Environment

**Linux/Mac:**
```bash
source venv/bin/activate
```

**Windows (Command Prompt):**
```cmd
venv\Scripts\activate
```

**Windows (PowerShell):**
```powershell
venv\Scripts\Activate.ps1
```

You should see `(venv)` at the beginning of your command prompt.

### Step 4: Upgrade pip (Recommended)
```bash
pip install --upgrade pip setuptools wheel
```

### Step 5: Install the Package

**Basic installation:**
```bash
pip install -e .
```

**With all optional features:**
```bash
pip install -e ".[all]"
```

**With development tools:**
```bash
pip install -e ".[dev]"
```

### Step 6: Verify Installation
```bash
forensic-toolbox --version
ftb --version
```

You should see: `Forensic Toolbox v1.0.0`

## Installation Options

### Option 1: Basic Installation
Installs only core dependencies (python-registry, python-evtx)
```bash
pip install -e .
```

### Option 2: Full Installation
Includes support for compressed prefetch files (Windows 10+) and memory analysis (Volatility 3)
```bash
pip install -e ".[all]"
```

### Option 3: Memory Analysis Only
Install Volatility 3 for memory dump analysis
```bash
pip install volatility3
```

### Option 4: Development Installation
Includes testing and development tools
```bash
pip install -e ".[dev]"
```

## Optional Features

### Memory Analysis with Volatility 3

To enable memory dump analysis, install Volatility 3:

```bash
# Install Volatility 3
pip install volatility3

# Or install with the 'all' extras
pip install -e ".[all]"
```

**Note:** On first use, Volatility 3 will automatically download symbol tables for the OS you're analyzing. This may take a few moments.

**Supported memory dump formats:**
- .raw, .mem, .dmp (raw memory dumps)
- .vmem (VMware snapshots - recommended)
- .lime (LiME format for Linux)
- And other common formats

## Using Makefile (Linux/Mac/WSL)

The Makefile provides convenient commands for common tasks:
```bash
# View all available commands
make help

# Create venv and install (basic)
make install

# Install with all features
make install-all

# Install for development
make install-dev

# Run tests
make test

# Format code
make format

# Lint code
make lint

# Run all checks
make check

# Clean build artifacts
make clean
```

## Directory Structure After Installation

forensic-toolbox/
├── venv/                    # Virtual environment (created)
│   ├── bin/                 # Executables (Linux/Mac)
│   ├── Scripts/             # Executables (Windows)
│   └── lib/                 # Installed packages
├── Toolbox/                 # Source code
│   ├── __init__.py
│   ├── toolbox_registry.py
│   ├── toolbox_prefetch.py
│   ├── toolbox_lnk.py
│   ├── toolbox_evtx.py
│   └── toolbox_volatility.py
├── main.py                  # Entry point
├── registry_mapping.py      # Registry keys configuration
├── evtx_mapping.py          # Event IDs configuration
├── volatility_mapping.py    # Volatility plugins configuration
├── pyproject.toml          # Package config
├── requirements.txt        # Dependencies
├── Makefile               # Build automation
└── README.md              # Documentation

## Running the Tool

After installation and activation of the virtual environment:
```bash
# Using full command
forensic-toolbox <file>

# Using short command
ftb <file>

# Examples
forensic-toolbox evidence.lnk
forensic-toolbox SOFTWARE --output results.json
ftb CALC.EXE-12345.pf
forensic-toolbox Security.evtx
forensic-toolbox memory.raw  # Memory dump analysis (requires Volatility 3)
```

## Troubleshooting

### "Command not found" after installation

**Problem:** `forensic-toolbox: command not found`

**Solution:** Make sure the virtual environment is activated:
```bash
# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### Permission denied (Linux/Mac)

**Problem:** Permission errors when running make

**Solution:**
```bash
chmod +x venv/bin/*
```

### pip install fails

**Problem:** Installation fails with dependency errors

**Solution:**
```bash
# Upgrade pip first
pip install --upgrade pip setuptools wheel

# Try installing dependencies separately
pip install python-registry
pip install -e .
```

### Python version too old

**Problem:** `python3: command not found` or version < 3.7

**Solution:** Install Python 3.7+ from python.org or use:
```bash
# Ubuntu/Debian
sudo apt install python3.9 python3.9-venv

# macOS (using Homebrew)
brew install python@3.9
```

### Windows: Script execution disabled

**Problem:** PowerShell script execution is disabled

**Solution:**
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate venv
venv\Scripts\Activate.ps1
```

## Uninstallation

### Remove the package only
```bash
pip uninstall forensic-toolbox
```

### Remove everything including venv
```bash
# Linux/Mac
make clean

# Or manually
rm -rf venv/
```
```cmd
# Windows
rmdir /s venv
```

## Updating

To update to the latest version:
```bash
# Activate venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Pull latest changes
git pull

# Reinstall
pip install -e .
```

## Alternative: System-wide Installation (Not Recommended)

If you want to install system-wide (not recommended for development):
```bash
# Without venv
pip install .

# Or from PyPI (once published)
pip install forensic-toolbox
```

## Next Steps

After successful installation:

1. Read the [README.md](README.md) for usage examples
2. Try analyzing sample files
3. Check out the API documentation
4. Run tests: `make test`

## Getting Help

If you encounter issues:

1. Check this installation guide
2. Visit the GitHub issues page
3. Contact: practical4n6@gmail.com