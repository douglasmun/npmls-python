# npmls-python - NPM Security Scanner (Python)

[![PyPI version](https://img.shields.io/pypi/v/npmls.svg)](https://pypi.org/project/npmls/)
[![Python versions](https://img.shields.io/pypi/pyversions/npmls.svg)](https://pypi.org/project/npmls/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/pypi/dm/npmls.svg)](https://pypi.org/project/npmls/)

A fast, cross-platform Python application that scans your entire system for npm modules and detects known malicious packages from recent supply chain attacks.

**Credits to the Original NPMLS Rust** https://github.com/h4x0r/npmls **and its author:** Albert Hui <albert@securityronin.com>

**Ported to NPMLS Python by:** Douglas Mun <douglasmun@yahoo.com>

## Features

- 🚀 **Lightning Fast**: Uses platform-specific optimizations:
  - **Linux**: `locate` database for instant lookups
  - **macOS**: Spotlight (`mdfind`) for fast filesystem queries  
  - **Windows**: PowerShell for directory enumeration
  - **Fallback**: Built-in parallel filesystem scanner

- 📊 **Multiple Output Formats**: Table, JSON, and CSV reporting
- ⚡ **Async Processing**: Concurrent scanning for maximum performance
- 🎯 **Threat Intelligence**: Online vulnerability feeds from authoritative sources
- 🌐 **Auto-Updates**: Automatically downloads latest threat intelligence

## Installation

The entire application is contained in a single `npmls.py` file, making it easy to:
- **Copy to any Python environment** without installation
- **Include in existing Python projects** as a module
- **Distribute as a standalone script** (just needs Python 3.8+)
- **Integrate into CI/CD pipelines** for security scanning

### From Source (Recommended)
```bash
# Clone the repository
git clone https://github.com/douglasmun/npmls-python

# Create virtual environment
python3 -m venv path/to/npmls-python
source npmls-python/bin/activate  # On Windows: venv\Scripts\activate
cd npmls-python

# Downloads the required python packages
python3.12 -m pip install -r requirements.txt

# Usage
python3 npmls.py --help

```

## Requirements

- **Python**: 3.8 or higher
- **Dependencies**:
  - `aiohttp` - Async HTTP client for downloading databases
  - `aiofiles` - Async file operations
  - `rich` - Beautiful terminal output and progress bars
  - `packaging` - Semantic version comparison for vulnerability matching

## Usage

### Basic Scan (Automatic Updates)
```bash
# Scan entire system - automatically downloads/updates database as needed
python3 npmls.py

# Show only malicious packages
python3 npmls.py --threats-only

# Verbose output with progress (shows download progress on first run)
python3 npmls.py --verbose
```

### Manual Database Control
```bash
# Force database update (optional - normally automatic)
python3 npmls.py --update-db

# Offline mode - skip all downloads (no threat detection in offline mode)
python3 npmls.py --offline
```

### Output Formats
```bash
# JSON output
python3 npmls.py --format json

# CSV output  
python3 npmls.py --format csv --output scan_results.csv

# Table output (default)
python3 npmls.py --format table

# List all known threats
python3 npmls.py --list-threats

# Search for specific threats
python3 npmls.py --list-threats chalk
```

### Command Line Options
```
usage: python3 npmls.py [-h] [-o OUTPUT] [--format {table,json,csv}] [-t] [-v]
             [--offline] [--update-db] [--list-threats [FILTER]]
             [--no-auto-files] [--force]

Fast cross-platform scanner for npm modules and malicious packages

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output results to file
  --format {table,json,csv}
                        Output format (default: table)
  -t, --threats-only    Only show packages matching known vulnerable versions
  -v, --verbose         Verbose output with detailed scan progress
  --offline             Offline mode - skip all downloads (no threat detection)
  --update-db           Update vulnerability database from online sources and exit
  --list-threats [FILTER]
                        List all known vulnerable packages and versions, then exit
  --no-auto-files       Disable automatic generation of JSON and CSV files
  --force               Force overwrite of existing output files without confirmation

Examples:
  python3 npmls.py                              # Scan entire system
  python3 npmls.py --threats-only               # Show only malicious packages
  python3 npmls.py --format json -o report.json # JSON output to file
  python3 npmls.py --list-threats               # List all known threats
  python3 npmls.py --offline                    # Offline mode (no threat detection)
```

## Sample Output

```
🔍 NPM Security Scanner
Scan entire file system for malicious npm packages and modules

🍎 Using macOS Spotlight (mdfind) for fast scanning...
✅ Found 234 node_modules directories
📦 Analyzing 234 node_modules directories...
📥 Loaded 1,247 vulnerabilities from cache (2h old) ✅

                    📦 NPM Package Security Scan Results                    
┌─────────────────────┬─────────┬─────────────┬─────────────┬──────────────────────┐
│ Package Name        │ Version │ Status      │ Threat Level│ Location             │
├─────────────────────┼─────────┼─────────────┼─────────────┼──────────────────────┤
│ chalk               │ 5.6.1   │ 🚨 MALICIOUS│ 🔴 Critical │ /Users/dev/project   │
│ debug               │ 4.4.2   │ 🚨 MALICIOUS│ 🔴 Critical │ /Users/dev/project   │
│ express             │ 4.18.2  │ ✅ Clean    │ —           │ /Users/dev/project   │
│ react               │ 18.2.0  │ ✅ Clean    │ —           │ /Users/dev/project   │
└─────────────────────┴─────────┴─────────────┴─────────────┴──────────────────────┘

📊 Summary: 1,234 total packages, 2 malicious

🚨 SECURITY ALERT - MALICIOUS PACKAGES DETECTED
═══════════════════════════════════════════════════════════

📦 Package: chalk@5.6.1
📍 Location: /Users/dev/project/node_modules/chalk
⚡ Threat Type: SupplyChainAttack
🔥 Severity: CRITICAL
📝 Description: Malicious version contains crypto wallet hijacking malware. Maintainer account compromised...
🏷️ CWE IDs: CWE-506
📊 CVSS Score: 9.8
📊 Source: OSV
🔗 References: https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx
────────────────────────────────────────────────────────────

🛡️ RECOMMENDED ACTIONS:
   1. 🚫 Immediately remove or downgrade affected packages
   2. 🔍 Check your package-lock.json for these versions
   3. 🔧 Audit your project dependencies: npm audit
   4. 🔧 Consider using npm audit fix for automated fixes
   5. 👁️ Monitor your systems for signs of compromise
   6. ⬆️ Update to latest secure versions when available
```

## How It Works

1. **Smart Database Updates**: Automatically downloads vulnerability data on first run or when cache is >1h old
2. **Fast Discovery**: Uses OS-specific tools for rapid filesystem scanning
3. **Package Analysis**: Parses `package.json` files to extract name/version info  
4. **Threat Matching**: Compares against cached vulnerability database
5. **Intelligent Reporting**: Provides actionable security insights

## Vulnerability Database Sources

The application automatically downloads and maintains vulnerability data from multiple authoritative sources:

### Primary Sources
- **[OSV Database](https://osv.dev/)**: Open Source Vulnerabilities database
  - Comprehensive vulnerability database with structured data
  - Real-time updates from multiple security sources
  - Covers npm ecosystem comprehensively
  - CVE mappings and severity scores
  - Detailed remediation guidance

### Coverage Includes
- **Recent Supply Chain Attacks**:
  - Real-world examples: event-stream, eslint-scope, ua-parser-js incidents
  - Actively monitors new threats as they emerge
- **Historical Threats**: Comprehensive database of documented npm supply chain attacks
- **CVE Database**: Known Common Vulnerabilities and Exposures
- **Malicious Package Detection**: Packages with confirmed malware, backdoors, or cryptocurrency miners
- **Typosquatting**: Detection of malicious packages impersonating popular libraries

### Database Updates
- **Automatic**: Downloads latest data on first run and when cache is >1 hour old
- **Manual**: Use `--update-db` flag to force immediate update
- **Offline Mode**: Use `--offline` to skip all downloads (no threat detection in offline mode)
- **Cache Location**: Stored in `~/.cache/npmls/` for optimal performance

## API Usage

You can also use npmls as a Python library for custom integrations:

```python
import asyncio
from npmls import Scanner, Reporter, ThreatDatabase

async def scan_for_threats():
    # Initialize scanner with custom settings
    scanner = Scanner(verbose=True, online_mode=True)
    await scanner.initialize()

    # Perform system-wide scan
    results = await scanner.scan_system()

    # Filter for vulnerable packages only
    vulnerable = [r for r in results if r.is_vulnerable]

    # Custom processing of results
    for result in vulnerable:
        print(f"⚠️  THREAT: {result.package.name}@{result.package.version}")
        print(f"   Severity: {result.threat.severity.value}")
        print(f"   Type: {result.threat.threat_type.value}")
        print(f"   Location: {result.package.path}")

    # Generate structured report
    reporter = Reporter(format_type="json", threats_only=True)
    await reporter.generate_report(results, output_path="threats.json")

# Run the scan
asyncio.run(scan_for_threats())
```

### Integration Examples

**CI/CD Pipeline Integration:**
```python
async def ci_security_check():
    """Fail CI build if vulnerable packages detected"""
    scanner = Scanner(verbose=False, online_mode=True)
    await scanner.initialize()
    results = await scanner.scan_system()

    vulnerable_count = sum(1 for r in results if r.is_vulnerable)
    if vulnerable_count > 0:
        print(f"❌ Security check FAILED: {vulnerable_count} vulnerable packages found")
        exit(1)
    else:
        print("✅ Security check PASSED: No threats detected")
        exit(0)
```

## Testing

```bash
# Run all tests
python3 test_npmis.py
```

## Development

### Code Quality Tools

```bash
# Format code
black npmls.py

# Lint code
flake8 npmls.py

# Type checking
mypy npmls.py

# All quality checks
black npmls.py && flake8 npmls.py && mypy npmls.py && pytest
```

### Project Structure

```
npmls/
├── npmls.py             # Main application file
├── requirements.txt     # Python dependencies
├── pyproject.toml       # Modern Python packaging
├── README.md            # Documentation
├── LICENSE              # MIT license
├── test_npmis.py        # Test suite
└── .github/             # GitHub Actions
    └── workflows/
        └── ci.yml
```

## Architecture

The Python implementation follows modern async/await patterns and professional Python practices:

- **Async/Await**: All I/O operations use `asyncio` for maximum performance
- **Type Hints**: Full type annotations for better code quality
- **Rich UI**: Beautiful terminal output with progress bars and colors
- **Modular Design**: Clean separation of concerns with dedicated classes
- **Error Handling**: Comprehensive error handling with graceful fallbacks
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Professional Packaging**: Standard Python packaging with `pyproject.toml`

## Performance

The Python version maintains the performance characteristics of the original Rust implementation:

- **Platform-optimized scanning** using native OS tools
- **Parallel processing** for multiple directory analysis
- **Efficient caching** of vulnerability data
- **Stream processing** of large vulnerability databases
- **Memory-efficient** parsing of ZIP archives

### Scanning Speed
- **Small projects** (< 10 node_modules): < 1 second
- **Medium projects** (< 100 node_modules): < 5 seconds
- **Large systems** (1000+ node_modules): < 30 seconds

### Memory Usage
- **Base memory**: ~20-50 MB (Python interpreter + application)
- **Database cache**: ~10-20 MB (varies with vulnerability count)
- **Scanning overhead**: ~5-10 MB per 1000 packages analyzed

### Database Performance
- **Package threat checking**: > 10,000 checks/second
- **Vulnerability database download**: 2-5 minutes (first run only)
- **Cache refresh**: < 30 seconds (subsequent updates)

## Security Notice

This tool is for defensive security purposes only. It helps identify potentially compromised npm packages on your system. Always verify findings and update to secure package versions.

## Comparison with Original Rust Version

| Feature | Python Version | Rust Version |
|---------|---------------|--------------|
| Performance | Fast (async) | Fastest (native) |
| Memory Usage | Moderate | Minimal |
| Installation | `pip install` | `cargo install` |
| Dependencies | 4 runtime deps | Self-contained binary |
| Platform Support | Cross-platform | Cross-platform |
| Database Updates | Automatic | Automatic |
| Output Formats | JSON/CSV/Table | JSON/CSV/Table |
| Maintenance | Easy (Python) | Moderate (Rust) |

Choose the Python version if you:
- Prefer Python ecosystem and tooling
- Need easy integration with Python applications
- Want simpler development and contribution process
- Are comfortable with pip/Python dependency management

Choose the original Rust version if you:
- Need maximum performance
- Prefer single-binary deployment
- Want minimal memory footprint
- Need the fastest possible scanning speed

## License

MIT License - see LICENSE file for details.
