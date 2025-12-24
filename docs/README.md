# 🔍 Forensic Toolbox
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey?style=for-the-badge" alt="Platform">
</p>
<p align="center">  [![Issues](https://img.shields.io/github/issues/Prof-GP/forensic-toolbox?color=d32f2f)](https://github.com/Prof-GP/forensic-toolbox/issues)
  [![Stars](https://img.shields.io/github/stars/Prof-GP/forensic-toolbox?style=social)](https://github.com/Prof-GP/forensic-toolbox/stargazers)
</p>
---

## ✨ Features

### 🎯 Automatic File Detection
Automatically identifies file types based on signatures and filenames - just point it at your evidence!

### 📁 Registry Analysis
Extract forensically significant data from Windows Registry hives:
- **Supported Hives**: SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS
- **Extracts**: Autoruns, network profiles, USB devices, user activity, installed applications, and more

### ⚡ Prefetch Parsing
Complete Windows Prefetch file parser with broad compatibility:
- **Versions Supported**: Windows XP through Windows 11
- **Handles**: Compressed prefetch files (Windows 10+)
- **Extracts**: Execution timestamps, run counts, loaded files, and directories

### 🔗 LNK File Analysis
Parse Windows shortcut files to uncover:
- Target information and timestamps
- Volume data and serial numbers
- Extra data blocks (TrackerData, ConsoleData, etc.)
- Potential MAC addresses in GUIDs

### 📋 EVTX Parsing
Parse Windows Event Logs from `C:\Windows\System32\winevt\Logs`:
- Commonly used Event IDs mapped automatically
- Individual PowerShell log parsing to see commands
- Add custom Event IDs to mappings or via command line
- Output to JSON and CSV formats

### 🧠 Memory Analysis
**NEW!** Volatility 3 integration for memory dump analysis:
- **Auto-detects** OS type (Windows, Linux, Mac)
- **Runs** curated forensically relevant plugins
- **Categories**: processes, network, files, registry, malware indicators, system info
- **Output formats**: text (default), JSON, CSV, markdown
- **Features**: Separate file per plugin, timeout handling, priority plugins for fast analysis

---

## 🚀 Installation

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

---

## 💻 Usage

### Command Line Interface

#### Basic Usage
```bash
# Automatically detect and parse any supported file
forensic-toolbox evidence.lnk
forensic-toolbox CALC.EXE-12345.pf
forensic-toolbox SOFTWARE
```

#### Registry Analysis
```bash
# Specify registry type explicitly
forensic-toolbox REGISTRY_FILE --type SOFTWARE

# Export results to file
forensic-toolbox SOFTWARE --output results.json
forensic-toolbox NTUSER.DAT --output user_activity.csv
```

#### Process Multiple Files
```bash
forensic-toolbox file1.lnk file2.pf NTUSER.DAT
```

#### EVTX Parsing
```bash
# Parse specific event IDs
forensic-toolbox Security.evtx --evtx-event 4688

# Parse entire logs directory
forensic-toolbox C:\Logs
```

#### Memory Dump Analysis
```bash
# Auto-detect OS and run all forensic plugins
forensic-toolbox memory.dmp

# Priority plugins only (RECOMMENDED for fast analysis)
forensic-toolbox memory.vmem --vol-priority-only

# Specific plugins
forensic-toolbox memory.raw --vol-plugins windows.pslist.PsList windows.netscan.NetScan

# Specific categories (FAST - excludes scanning plugins)
forensic-toolbox memory.dmp --vol-categories processes network malware_indicators

# Include scanning plugins (SLOW - can take 30+ minutes)
forensic-toolbox memory.dmp --vol-categories processes processes_scan malware_scan

# Different output formats
forensic-toolbox memory.dmp --vol-format json      # JSON format
forensic-toolbox memory.dmp --vol-format csv       # CSV format
forensic-toolbox memory.dmp --vol-format markdown  # Markdown format
```

### Short Command
Use `ftb` as shorthand for `forensic-toolbox`:
```bash
ftb SOFTWARE --output results.json
```

### 🐍 Python API

```python
from Toolbox.toolbox_registry import ToolboxRegistry
from Toolbox.toolbox_prefetch import ToolboxPrefetch
from Toolbox.toolbox_lnk import ToolboxLnk
from Toolbox.toolbox_volatility import ToolboxVolatility

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

# Analyze memory dump
vol = ToolboxVolatility('memory.dmp')
vol.detect_os()
vol.run_forensic_analysis()
vol.print_summary()
```

---

## 📦 Supported File Types

<table>
<thead>
<tr>
<th>Type</th>
<th>Files</th>
<th>Key Information Extracted</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Registry Hives</strong></td>
<td>SOFTWARE, SYSTEM, SAM, NTUSER.DAT, SECURITY, USRCLASS.DAT</td>
<td>Installed apps, autoruns, network profiles, USB devices, user activity, security policies</td>
</tr>
<tr>
<td><strong>Prefetch Files</strong></td>
<td>.pf (XP through Win 11)</td>
<td>Execution timestamps, run counts, loaded DLLs, accessed directories</td>
</tr>
<tr>
<td><strong>Windows Shortcuts</strong></td>
<td>.lnk</td>
<td>Target paths, timestamps, volume info, network shares, MAC addresses</td>
</tr>
<tr>
<td><strong>Event Logs</strong></td>
<td>.evtx</td>
<td>System events, user activity, PowerShell commands, security events</td>
</tr>
<tr>
<td><strong>Memory Dumps</strong></td>
<td>.vmem, .raw, .mem, .dmp, .lime, .dump, .img, .bin, .dd</td>
<td>Running processes, network connections, loaded DLLs, registry data, malware indicators</td>
</tr>
</tbody>
</table>

---

## 🧪 Memory Analysis Details

### Memory Acquisition Methods

**Recommended approach for VM analysis:**
1. **Pause/Suspend the VM** - Creates a .vmem file with full memory state
2. **Copy forensic artifacts to host** - Ensure all analysis files are extracted first
3. **Analyze the .vmem file** - Use this toolbox on the paused VM's memory

### Plugin Categories

| Category | Speed | Description |
|----------|-------|-------------|
| **processes** | ⚡ FAST | Process listings, trees, command lines, DLLs |
| **processes_scan** | 🐌 SLOW | Hidden process scanning (30+ minutes) |
| **network** | ⚡ FAST | Network connections, sockets, netstat |
| **registry** | ⚡ FAST | Registry hives, UserAssist, registry keys |
| **files** | 🐌 SLOW | File object scanning |
| **malware_indicators** | ⚡ FAST | Code injection, kernel callbacks, SSDT hooks |
| **malware_scan** | 🐌 SLOW | VAD analysis, driver scanning (30+ minutes) |
| **system_info** | ⚡ FAST | OS information, services, drivers |

### Performance Tips

- ✅ Use `--vol-priority-only` for quick triage (1-5 minutes)
- ✅ Use `--vol-categories processes network malware_indicators` for fast comprehensive analysis
- ⚠️ Avoid `processes_scan`, `malware_scan`, and `files` unless deep scanning is needed
- ⚠️ Scanning plugins can take 10-60+ minutes on large dumps

### Example Output Structure

```
memory_volatility_output/
├── analysis_summary.json
├── windows_info_Info.txt
├── windows_pslist_PsList.txt
├── windows_pstree_PsTree.txt
├── windows_netscan_NetScan.txt
├── windows_cmdline_CmdLine.txt
└── ...
```

---

## 🎯 Use Cases

| Use Case | Description |
|----------|-------------|
| **Digital Forensics** | Extract evidence from Windows, Linux, and Mac systems |
| **Incident Response** | Analyze program execution, user activity, and live memory |
| **Malware Analysis** | Identify persistence mechanisms, code injection, and rootkits |
| **System Auditing** | Review installed software and system configuration |
| **Timeline Analysis** | Build execution timelines from multiple artifacts |
| **Memory Forensics** | Analyze memory dumps for running processes, network connections, and hidden malware |

---

## 📊 Output Formats

- **Console**: Human-readable formatted output
- **JSON**: Machine-readable structured data
- **CSV**: Spreadsheet-compatible format
- **Markdown**: Documentation-friendly format (memory analysis)

---

## 📝 Examples

### Parse SOFTWARE Registry Hive
```bash
forensic-toolbox SOFTWARE --output software_analysis.json
```

**Output includes:**
- ✓ Installed applications
- ✓ Autorun entries
- ✓ Network profiles
- ✓ System version information
- ✓ USB device history

### Analyze Prefetch File
```bash
forensic-toolbox CHROME.EXE-12345ABC.pf
```

**Output includes:**
- ✓ Executable name and hash
- ✓ Run count and last execution times
- ✓ Referenced DLLs and files
- ✓ Accessed directories
- ✓ Volume information

### Parse LNK File
```bash
forensic-toolbox "Recent Document.lnk"
```

**Output includes:**
- ✓ Target file path
- ✓ Timestamps (created, modified, accessed)
- ✓ Volume serial number
- ✓ Network share information
- ✓ MAC address (if present in tracker data)

### Parse EVTX File
```bash
forensic-toolbox Security.evtx
```

**Output includes:**
- ✓ Processing event count
- ✓ Extracted events
- ✓ Event information for analysis
- ✓ Warnings if event count is too large

### Analyze Memory Dump
```bash
forensic-toolbox memory.dmp
```

**Output includes:**
- ✓ OS detection results (Windows/Linux/Mac)
- ✓ Separate output file per plugin
- ✓ Analysis summary with execution statistics
- ✓ Process listings, network connections, DLLs, malware indicators, and more

---

## 🛠️ Development

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

---

## 📁 Project Structure

```
forensic-toolbox/
├── Toolbox/
│   ├── __init__.py
│   ├── toolbox_registry.py      # Registry hive parser
│   ├── toolbox_prefetch.py      # Prefetch file parser
│   ├── toolbox_lnk.py           # LNK file parser
│   ├── toolbox_evtx.py          # EVTX parser
│   └── toolbox_volatility.py    # Memory analysis (Volatility 3)
├── main.py                       # Main entry point
├── registry_mapping.py           # Forensic registry keys configuration
├── evtx_mapping.py               # Forensic event ID configuration
├── volatility_mapping.py         # Volatility plugins configuration
├── pyproject.toml                # Package configuration
├── requirements.txt              # Dependencies
├── Makefile                      # Build automation
└── README.md                     # This file
```

---

## 📋 Requirements

- **Python**: 3.7+
- **python-registry**: >=1.3.1
- **python-evtx**: >=0.8.0
- **pyxpress**: >=0.1.0 (optional, for compressed prefetch files)
- **Volatility 3**: Command-line tool (for memory analysis)
  - Download from: [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
  - Ensure `vol.exe` or `vol3` is in your system PATH
  - Alternative: `pip install volatility3` (then use `python -m volatility3`)

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 👤 Author

**Prof-GP**
- Email: practical4n6@gmail.com
- GitHub: [@Prof-GP](https://github.com/Prof-GP)

---

## 🙏 Acknowledgments

- **python-registry** library by Willi Ballenthin
- **python-evtx** library for EVTX parsing
- **Volatility Foundation** for Volatility 3 framework
- **Microsoft** documentation on Windows file formats
- **Digital forensics community** for ongoing support and feedback

---

## 💬 Support

For issues, questions, or contributions, please visit:

🔗 [https://github.com/Prof-GP/forensic-toolbox/issues](https://github.com/Prof-GP/forensic-toolbox/issues)

---

<p align="center">
  <sub>Built with ❤️ for the digital forensics community</sub>
</p>
