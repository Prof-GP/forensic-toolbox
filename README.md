# Forensic Toolbox

A comprehensive Python toolkit for parsing Windows forensic artifacts including Registry hives, Prefetch files, and Windows shortcuts (.lnk files).

## Features

- **Automatic File Detection**: Automatically identifies file types based on signatures and filenames
- **Registry Analysis**: Extracts forensically significant data from Windows Registry hives
  - SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS hives
  - Autoruns, network profiles, USB devices, user activity, and more
- **Prefetch Parsing**: Complete Windows Prefetch file parser
  - Supports Windows XP through Windows 11
  - Handles compressed prefetch files (Windows 10+)
  - Extracts execution timestamps, run counts, loaded files, and directories
- **LNK File Analysis**: Parses Windows shortcut files
  - Extracts target information, timestamps, volume data
  - Decodes extra data blocks (TrackerData, ConsoleData, etc.)
  - Identifies potential MAC addresses in GUIDs

## Installation

### Quick Install (Recommended)
```bash
# Clone the repository
git clone https://github.com/Prof-GP/forensic-toolbox.git
cd forensic-toolbox

# Create virtual environment and install
make install

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### Manual Installation
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install package
pip install -e .
```

### Install with Optional Dependencies
```bash
# Install with all optional features (including compressed prefetch support)
make install-all

# Or manually
pip install -e ".[all]"
```

## Usage

### Command Line Interface
```bash
# Automatically detect and parse any supported file
forensic-toolbox evidence.lnk
forensic-toolbox CALC.EXE-12345.pf
forensic-toolbox SOFTWARE

# Specify registry type explicitly
forensic-toolbox REGISTRY_FILE --type SOFTWARE

# Export results to file
forensic-toolbox SOFTWARE --output results.json
forensic-toolbox NTUSER.DAT --output user_activity.csv

# Process multiple files
forensic-toolbox file1.lnk file2.pf NTUSER.DAT

# Enable verbose output
forensic-toolbox evidence.lnk --verbose
```

### Short Command
```bash
# Use 'ftb' as shorthand for 'forensic-toolbox'
ftb SOFTWARE --output results.json
```

### Python API
```python
from Toolbox.toolbox_registry import ToolboxRegistry
from Toolbox.toolbox_prefetch import ToolboxPrefetch
from Toolbox.toolbox_lnk import ToolboxLnk

# Parse registry hive
reg = ToolboxRegistry('SOFTWARE', 'SOFTWARE')
results = reg.valuable_keys()
reg.print_results(results)

# Parse prefetch file
with ToolboxPrefetch('CALC.EXE-12345.pf') as parser:
    if parser.parse():
        parser.print_summary()

# Parse LNK file
lnk = ToolboxLnk('shortcut.lnk')
```

## Supported File Types

### Registry Hives
- **SOFTWARE**: System information, installed applications, autoruns, network profiles
- **SYSTEM**: Computer name, network interfaces, USB devices, services
- **SAM**: Local user accounts, login history
- **NTUSER.DAT**: User-specific activity (recent documents, typed paths, UserAssist)
- **SECURITY**: Security policy settings, audit configuration
- **USRCLASS.DAT**: User shell bags and file associations

### Prefetch Files (.pf)
- Windows XP (version 17)
- Windows Vista/7 (version 23)
- Windows 8/8.1 (version 26)
- Windows 10/11 (version 30)
- Compressed prefetch files (Windows 10+)

### Windows Shortcuts (.lnk)
- Target information and paths
- Creation, access, and modification timestamps
- Volume information and serial numbers
- Network share information
- Extra data blocks (console properties, tracker data, etc.)

## Development

### Running Tests
```bash
make test
```

### Code Formatting
```bash
make format
```

### Linting
```bash
make lint
```

### Run All Checks
```bash
make check
```

## Project Structure

forensic-toolbox/
├── Toolbox/
│   ├── init.py
│   ├── toolbox_registry.py      # Registry hive parser
│   ├── toolbox_prefetch.py      # Prefetch file parser
│   └── toolbox_lnk.py           # LNK file parser
├── main.py                       # Main entry point
├── registry_mapping.py           # Forensic registry keys configuration
├── pyproject.toml               # Package configuration
├── requirements.txt             # Dependencies
├── Makefile                     # Build automation
└── README.md                    # This file

## Requirements

- Python 3.7+
- python-registry>=1.3.1
- pyxpress>=0.1.0 (optional, for compressed prefetch files)

## Use Cases

- **Digital Forensics**: Extract evidence from Windows systems
- **Incident Response**: Analyze program execution and user activity
- **Malware Analysis**: Identify persistence mechanisms and executed programs
- **System Auditing**: Review installed software and system configuration
- **Timeline Analysis**: Build execution timelines from multiple artifacts

## Output Formats

- **Console**: Human-readable formatted output
- **JSON**: Machine-readable structured data
- **CSV**: Spreadsheet-compatible format

## Examples

### Parse SOFTWARE Registry Hive
```bash
forensic-toolbox SOFTWARE --output software_analysis.json
```

Output includes:
- Installed applications
- Autorun entries
- Network profiles
- System version information
- USB device history

### Analyze Prefetch File
```bash
forensic-toolbox CHROME.EXE-12345ABC.pf
```

Output includes:
- Executable name and hash
- Run count and last execution times
- Referenced DLLs and files
- Accessed directories
- Volume information

### Parse LNK File
```bash
forensic-toolbox "Recent Document.lnk"
```

Output includes:
- Target file path
- Timestamps (created, modified, accessed)
- Volume serial number
- Network share information
- MAC address (if present in tracker data)

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Prof-GP - practical4n6@gmail.com

## Acknowledgments

- python-registry library by Willi Ballenthin
- Microsoft documentation on Windows file formats
- Digital forensics community

## Support

For issues, questions, or contributions, please visit:
https://github.com/Prof-GP/forensic-toolbox/issues