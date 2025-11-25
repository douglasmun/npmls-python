# npmls - NPM Security Scanner (Python)

[![PyPI version](https://img.shields.io/pypi/v/npmls.svg)](https://pypi.org/project/npmls/)
[![Python versions](https://img.shields.io/pypi/pyversions/npmls.svg)](https://pypi.org/project/npmls/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/pypi/dm/npmls.svg)](https://pypi.org/project/npmls/)

A fast, cross-platform Python application that scans your entire system for npm modules and detects known malicious packages from recent supply chain attacks.

**Credits to the Original NPMLS Rust Author:** Albert Hui <albert@securityronin.com>

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

### From PyPI (Recommended)
```bash
# Install the latest stable version
pip install npmls

# Or with development dependencies
pip install "npmls[dev]"

# Windows users may want additional features
pip install "npmls[windows]"
```

### From Source
```bash
# Clone the repository
git clone https://github.com/h4x0r/npmls.git
cd npmls

# Install in development mode
pip install -e .

# Or install with all dependencies
pip install -e ".[dev,windows]"
```

### Development Installation
```bash
# Clone and set up for development
git clone https://github.com/h4x0r/npmls.git
cd npmls

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black npmls.py

# Type checking
mypy npmls.py
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
npmls

# Show only malicious packages
npmls --threats-only

# Verbose output with progress (shows download progress on first run)
npmls --verbose
```

### Manual Database Control
```bash
# Force database update (optional - normally automatic)
npmls --update-db

# Offline mode - skip all downloads (no threat detection in offline mode)
npmls --offline
```

### Output Formats
```bash
# JSON output
npmls --format json

# CSV output  
npmls --format csv --output scan_results.csv

# Table output (default)
npmls --format table

# List all known threats
npmls --list-threats

# Search for specific threats
npmls --list-threats chalk
```

### Command Line Options
```
usage: npmls [-h] [-o OUTPUT] [--format {table,json,csv}] [-t] [-v]
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
  npmls                              # Scan entire system
  npmls --threats-only               # Show only malicious packages
  npmls --format json -o report.json # JSON output to file
  npmls --list-threats               # List all known threats
  npmls --offline                    # Offline mode (no threat detection)
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

## Deployment

### Docker Container

You can run npmls in a Docker container for isolated, reproducible scans:

```dockerfile
FROM python:3.11-slim

# Copy application files
WORKDIR /app
COPY npmls.py requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set entry point
ENTRYPOINT ["python", "npmls.py"]

# Example usage:
# docker build -t npmls .
# docker run -v /path/to/scan:/scan npmls /scan
```

### Standalone Script

The entire application is contained in a single `npmls.py` file, making it easy to:
- **Copy to any Python environment** without installation
- **Include in existing Python projects** as a module
- **Distribute as a standalone script** (just needs Python 3.8+)
- **Integrate into CI/CD pipelines** for security scanning

Simply copy `npmls.py` and install the 4 dependencies:
```bash
pip install aiohttp aiofiles rich packaging
python npmls.py
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=npmls

# Run only unit tests
pytest -m unit

# Run only integration tests (slower)
pytest -m integration

# Verbose test output
pytest -v
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
        ├── ci.yml
        └── release.yml
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Format code (`black .`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

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

Choose the Original Rust version if you:
- Need maximum performance
- Prefer single-binary deployment
- Want minimal memory footprint
- Need the fastest possible scanning speed

## License

MIT License - see LICENSE file for details.

## Changelog

### v1.0 (2024-11-25)
- Production-ready Python implementation
- Feature parity with original Rust version
- Async/await architecture for high performance
- Rich terminal UI with progress bars
- Comprehensive test suite with 80%+ coverage
- Professional Python packaging with pyproject.toml
- OSV vulnerability database integration
- Cross-platform support (Windows, macOS, Linux)
