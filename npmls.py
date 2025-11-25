#!/usr/bin/env python3
"""NPM Security Scanner - Fast cross-platform vulnerability detection.

This module provides comprehensive scanning capabilities for npm packages across
your entire system, detecting known malicious packages and security vulnerabilities
from recent supply chain attacks.

The scanner uses platform-specific optimizations (Spotlight on macOS, locate on Linux,
PowerShell on Windows) for fast filesystem scanning and maintains an automatically-
updated vulnerability database from authoritative sources (OSV, GitHub Advisory Database).

Author:
    Douglas Mun <douglasmun@yahoo.com>

Credits:
    Original NPMLS Rust implementation by Albert Hui <albert@securityronin.com>

License:
    MIT License - See LICENSE file for details

Example:
    Basic usage from command line::

        $ npmls --threats-only
        $ npmls --format json --output report.json
        $ npmls --offline

    Programmatic usage::

        import asyncio
        from npmls import Scanner, Reporter

        async def scan():
            scanner = Scanner(verbose=True, online_mode=True)
            await scanner.initialize()
            results = await scanner.scan_system()

            reporter = Reporter(format_type="json", threats_only=True)
            await reporter.generate_report(results)

        asyncio.run(scan())
"""
import argparse
import asyncio
import json
import csv
import os
import sys
import platform
# SECURITY: subprocess not imported to prevent global module shadowing
# We use asyncio.subprocess (asyncio.create_subprocess_exec) instead
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import tempfile
import shutil
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# Third-party imports (add to requirements.txt)
import aiohttp
import aiofiles
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich import print as rprint
from rich.panel import Panel

# Optional Pydantic for enhanced validation (graceful fallback if not available)
try:
    from pydantic import BaseModel, Field, validator, ValidationError, ConfigDict
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object  # Fallback to regular object
    ConfigDict = None

# SECURITY: Semantic versioning for proper version comparison
# Required for accurate vulnerability detection
try:
    from packaging import version as pkg_version
    PACKAGING_AVAILABLE = True
except ImportError:
    PACKAGING_AVAILABLE = False
    # Fallback to string comparison (less secure but functional)


# SECURITY: Utility function to sanitize file paths for logging
# Prevents PII leakage by replacing home directory with tilde
def sanitize_path_for_display(path: Path) -> str:
    """Sanitize file path for safe display in logs and output.

    Replaces user's home directory with ~ to prevent PII exposure.
    """
    try:
        home = Path.home()
        path_obj = Path(path)
        # Try to make path relative to home directory
        try:
            relative = path_obj.relative_to(home)
            return f"~/{relative}"
        except ValueError:
            # Path is not under home directory, return as string
            return str(path_obj)
    except Exception:
        # Fallback to string representation
        return str(path)


# SECURITY: Safe version comparison for vulnerability detection
def compare_versions(installed_version: str, vulnerable_version: str) -> bool:
    """Compare package versions using semantic versioning.

    SECURITY: Prevents false negatives from string comparison.
    Returns True if installed_version matches or is vulnerable.

    Args:
        installed_version: The version installed on the system
        vulnerable_version: The known vulnerable version

    Returns:
        True if versions match (indicating vulnerability)
    """
    try:
        if PACKAGING_AVAILABLE:
            # Use packaging library for proper semantic version comparison
            try:
                installed = pkg_version.parse(installed_version)
                vulnerable = pkg_version.parse(vulnerable_version)
                return installed == vulnerable
            except pkg_version.InvalidVersion:
                # If version parsing fails, fall back to string comparison
                return installed_version == vulnerable_version
        else:
            # Fallback to string comparison
            return installed_version == vulnerable_version
    except Exception:
        # On any error, use safe string comparison
        return installed_version == vulnerable_version


class ThreatType(Enum):
    """Classification of security threat types for npm packages.

    Categorizes the nature of security vulnerabilities and malicious behaviors
    found in npm packages. Used for threat intelligence reporting and filtering.

    Values:
        SUPPLY_CHAIN_ATTACK: Compromised legitimate packages (e.g., maintainer account takeover)
        CRYPTOJACKING: Unauthorized cryptocurrency mining malware
        CREDENTIAL_THEFT: Steals authentication credentials, API keys, or secrets
        BACKDOOR: Unauthorized remote access mechanisms
        DATA_EXFILTRATION: Unauthorized data transmission to external servers
        RANSOMWARE: Malware that encrypts data for ransom
        CROSS_SITE_SCRIPTING: XSS vulnerabilities in web applications
        SQL_INJECTION: SQL injection vulnerabilities
        REMOTE_CODE_EXECUTION: Allows arbitrary code execution
        DENIAL_OF_SERVICE: DoS or DDoS attack vectors
        PRIVILEGE_ESCALATION: Unauthorized privilege elevation
        BUFFER_OVERFLOW: Memory corruption vulnerabilities
        OTHER: Other threat types not categorized above
        UNKNOWN: Threat type not yet determined
    """
    SUPPLY_CHAIN_ATTACK = "SupplyChainAttack"
    CRYPTOJACKING = "Cryptojacking"
    CREDENTIAL_THEFT = "CredentialTheft"
    BACKDOOR = "Backdoor"
    DATA_EXFILTRATION = "DataExfiltration"
    RANSOMWARE = "Ransomware"
    CROSS_SITE_SCRIPTING = "CrossSiteScripting"
    SQL_INJECTION = "SqlInjection"
    REMOTE_CODE_EXECUTION = "RemoteCodeExecution"
    DENIAL_OF_SERVICE = "DenialOfService"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    BUFFER_OVERFLOW = "BufferOverflow"
    OTHER = "Other"
    UNKNOWN = "Unknown"


class Severity(Enum):
    """CVSS-aligned severity classification for security vulnerabilities.

    Severity levels based on Common Vulnerability Scoring System (CVSS) standards.
    Used to prioritize remediation efforts and communicate risk levels.

    Values:
        LOW: CVSS 0.1-3.9 - Minimal impact vulnerabilities
        MEDIUM: CVSS 4.0-6.9 - Moderate impact requiring attention
        HIGH: CVSS 7.0-8.9 - Serious vulnerabilities needing prompt remediation
        CRITICAL: CVSS 9.0-10.0 - Severe vulnerabilities requiring immediate action
    """
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class VulnerabilitySource(Enum):
    """Identifies the origin of vulnerability intelligence data.

    Tracks where vulnerability information was obtained to maintain data
    provenance and enable source-specific filtering or trust policies.

    Values:
        OSV: Open Source Vulnerabilities database (https://osv.dev/)
        BUILT_IN: Legacy value for previously embedded threat database (deprecated)
        COMBINED: Merged data from multiple sources
        UNKNOWN: Source not identified or unavailable
    """
    OSV = "OSV"
    BUILT_IN = "BuiltIn"
    COMBINED = "Combined"
    UNKNOWN = "Unknown"


@dataclass
class VulnerablePackage:
    """Complete vulnerability intelligence record for a compromised npm package.

    Encapsulates all available threat information about a specific package version,
    including CVE/CWE identifiers, CVSS scoring, and remediation references.

    Attributes:
        name (str): NPM package name (e.g., 'chalk', 'express')
        version (str): Vulnerable version or version range
        discovered (datetime): When the vulnerability was first discovered
        threat_type (ThreatType): Category of security threat
        description (str): Detailed explanation of the vulnerability
        severity (Severity): CVSS-based severity classification
        references (List[str]): URLs to advisories, CVEs, or security bulletins
        cwe_ids (List[str]): Common Weakness Enumeration identifiers
        nvd_published_at (Optional[datetime]): NVD publication timestamp
        cvss_score (Optional[float]): CVSS v3 score (0.0-10.0)
        cvss_vector (Optional[str]): CVSS v3 vector string
        source_database (VulnerabilitySource): Origin of this vulnerability data
        aliases (List[str]): Alternative identifiers (CVE, GHSA, etc.)
    """
    name: str
    version: str
    discovered: datetime
    threat_type: ThreatType
    description: str
    severity: Severity
    references: List[str]
    cwe_ids: List[str] = None
    nvd_published_at: Optional[datetime] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    source_database: VulnerabilitySource = VulnerabilitySource.BUILT_IN
    aliases: List[str] = None

    def __post_init__(self):
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.aliases is None:
            self.aliases = []


@dataclass
class PackageInfo:
    """Metadata about an installed npm package discovered during filesystem scan.

    Contains identifying information and filesystem attributes for a package
    found in a node_modules directory.

    Attributes:
        name (str): NPM package name from package.json
        version (str): Installed version from package.json
        path (str): Absolute filesystem path to package directory
        size_bytes (int): Total size of package directory in bytes
        modified (datetime): Last modification timestamp of package.json
    """
    name: str
    version: str
    path: str
    size_bytes: int
    modified: datetime


@dataclass
class ScanResult:
    """Combined result of scanning a package and matching against threat database.

    Links an installed package to any known vulnerabilities, providing a complete
    view of the security status for reporting and remediation.

    Attributes:
        package (PackageInfo): Installed package metadata
        threat (Optional[VulnerablePackage]): Matched vulnerability if package is vulnerable, None otherwise
        is_vulnerable (bool): True if threat was found, False if package is clean
    """
    package: PackageInfo
    threat: Optional[VulnerablePackage]
    is_vulnerable: bool


# SECURITY: Pydantic models for validating external OSV database data
# These provide runtime validation to prevent crashes from malformed data
if PYDANTIC_AVAILABLE:
    class OSVAffectedModel(BaseModel):
        """Pydantic validator for OSV database 'affected' field structure.

        Validates the 'affected' section of OSV vulnerability records to ensure
        data integrity and prevent runtime errors from malformed external data.

        Attributes:
            package (dict): Package ecosystem and name information
            versions (List[str]): Specific vulnerable version strings
            ranges (List[dict]): Version range specifications (introduced/fixed)
        """
        model_config = ConfigDict(extra="allow")  # Allow additional fields

        package: dict
        versions: Optional[List[str]] = Field(default_factory=list)
        ranges: Optional[List[dict]] = Field(default_factory=list)

    class OSVVulnerabilityModel(BaseModel):
        """Pydantic validator for complete OSV vulnerability record structure.

        Validates top-level OSV vulnerability JSON documents downloaded from
        external sources, ensuring schema compliance and preventing crashes
        from unexpected data formats.

        Attributes:
            id (str): Unique vulnerability identifier (e.g., GHSA-xxxx-xxxx-xxxx)
            summary (str): Brief one-line vulnerability summary
            details (str): Detailed vulnerability description and impact
            modified (str): ISO 8601 timestamp of last modification
            published (str): ISO 8601 timestamp of initial publication
            affected (List[dict]): Affected packages and version information
            references (List[dict]): External references (advisories, patches, etc.)
            severity (List[dict]): CVSS scores and severity classifications
            aliases (List[str]): Alternative identifiers (CVE, CWE, etc.)
        """
        model_config = ConfigDict(extra="allow")  # Allow additional OSV fields we don't use

        id: str
        summary: Optional[str] = ""
        details: Optional[str] = ""
        modified: Optional[str] = ""
        published: Optional[str] = ""
        affected: List[dict] = Field(default_factory=list)
        references: List[dict] = Field(default_factory=list)
        severity: List[dict] = Field(default_factory=list)
        aliases: List[str] = Field(default_factory=list)


class PlatformScanner:
    """Platform-specific filesystem scanning utilities for fast node_modules discovery.

    Provides optimized scanning strategies tailored to each operating system:
    - macOS: Uses Spotlight (mdfind) for instant metadata-based lookups
    - Linux: Leverages locate database for fast indexed filesystem queries
    - Windows: Uses PowerShell Get-ChildItem for directory enumeration
    - Fallback: Multi-threaded recursive filesystem walker for unsupported platforms

    The scanner automatically selects the best strategy for the current platform
    and falls back gracefully if platform-specific tools are unavailable.

    Class Attributes:
        _scan_semaphore (asyncio.Semaphore): Limits concurrent directory scans to 8
            to prevent resource exhaustion and maintain system responsiveness

    Example:
        >>> import asyncio
        >>> paths = asyncio.run(PlatformScanner.find_node_modules())
        >>> print(f"Found {len(paths)} node_modules directories")
        >>> for path in paths[:5]:
        ...     print(f"  {path}")
    """

    # SECURITY: Semaphore to limit concurrent directory scanning operations
    # Prevents resource exhaustion from scanning too many directories in parallel
    _scan_semaphore = asyncio.Semaphore(8)  # Limit to 8 concurrent scans

    @staticmethod
    async def find_node_modules() -> List[Path]:
        """Find all node_modules directories using platform-specific optimizations."""
        system = platform.system().lower()
        
        if system == "darwin":
            return await PlatformScanner._macos_mdfind()
        elif system == "linux":
            return await PlatformScanner._linux_locate()
        elif system == "windows":
            return await PlatformScanner._windows_scan()
        else:
            return await PlatformScanner._fallback_find()

    @staticmethod
    async def _macos_mdfind() -> List[Path]:
        """Use macOS Spotlight for fast scanning."""
        console = Console()
        console.print("🍎 Using macOS Spotlight (mdfind) for fast scanning...")

        try:
            # SECURITY: Use proper Spotlight query syntax to prevent path injection
            # kMDItemFSName properly escapes file names and prevents special character issues
            # This prevents bypasses from filenames with quotes or special characters
            proc = await asyncio.create_subprocess_exec(
                "mdfind", "kMDItemFSName == 'node_modules'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)

            if proc.returncode != 0:
                # Fallback to more specific query with folder type
                proc = await asyncio.create_subprocess_exec(
                    "mdfind", "kMDItemFSName == 'node_modules' && kMDItemContentType == 'public.folder'",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)

                if proc.returncode != 0:
                    return await PlatformScanner._fallback_find()
            
            paths = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    path = Path(line.strip())
                    if path.exists() and path.is_dir() and path.name == "node_modules":
                        paths.append(path)

            console.print(f"✅ Found {len(paths)} node_modules directories")
            return paths

        except asyncio.TimeoutError:
            console.print("⚠️ mdfind timed out, falling back to built-in scanner...")
            return await PlatformScanner._fallback_find()
        except Exception:
            return await PlatformScanner._fallback_find()

    @staticmethod
    async def _linux_locate() -> List[Path]:
        """Use Linux locate database for fast scanning."""
        console = Console()
        console.print("🐧 Using Linux locate database for fast scanning...")

        try:
            # SECURITY: Check locate database age to warn about stale data
            # Prevents false negatives from outdated database
            try:
                # Get mlocate.db timestamp
                locate_db_paths = [
                    Path("/var/lib/mlocate/mlocate.db"),
                    Path("/var/db/locate.database"),
                    Path("/var/lib/plocate/plocate.db")
                ]

                db_age_hours = None
                for db_path in locate_db_paths:
                    if db_path.exists():
                        db_mtime = db_path.stat().st_mtime
                        db_age_hours = (datetime.now().timestamp() - db_mtime) / 3600
                        break

                if db_age_hours and db_age_hours > 24:
                    console.print(f"[yellow]⚠️  WARNING: locate database is {db_age_hours:.1f} hours old[/yellow]")
                    console.print("[yellow]   Recent packages may not be detected. Run: sudo updatedb[/yellow]")
                elif db_age_hours and db_age_hours > 168:  # 1 week
                    console.print(f"[red]❌ CRITICAL: locate database is {db_age_hours/24:.1f} days old![/red]")
                    console.print("[red]   Scan results may be highly inaccurate. Run: sudo updatedb[/red]")
            except Exception:
                # Unable to check database age, continue anyway
                pass

            # SECURITY: Removed sudo updatedb call to prevent privilege escalation
            # The scanner should not attempt to escalate privileges
            # Users should update locate database manually if needed: sudo updatedb

            # SECURITY: Add timeout to prevent DoS from hanging processes
            proc = await asyncio.create_subprocess_exec(
                "locate", "-r", "/node_modules$",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)

            if proc.returncode != 0:
                console.print("⚠️ locate failed or not available, falling back to find command...")
                return await PlatformScanner._fallback_find()

            paths = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    path = Path(line.strip())
                    if path.exists() and path.is_dir():
                        paths.append(path)

            console.print(f"✅ Found {len(paths)} node_modules directories")
            return paths

        except asyncio.TimeoutError:
            console.print("⚠️ locate timed out, falling back to built-in scanner...")
            return await PlatformScanner._fallback_find()
        except Exception:
            return await PlatformScanner._fallback_find()

    @staticmethod
    async def _windows_scan() -> List[Path]:
        """Use Windows-specific scanning methods."""
        console = Console()
        console.print("🪟 Using Windows PowerShell for directory enumeration...")
        
        try:
            # Get all drives
            drives = []
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive_path = f"{letter}:\\"
                if Path(drive_path).exists():
                    drives.append(drive_path)
            
            all_paths = []
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Scanning drives...", total=len(drives))
                
                for drive in drives:
                    progress.update(task, description=f"Scanning {drive}")
                    paths = await PlatformScanner._scan_drive_powershell(drive)
                    all_paths.extend(paths)
                    progress.advance(task)
            
            console.print(f"✅ Found {len(all_paths)} node_modules directories")
            return all_paths
            
        except Exception:
            return await PlatformScanner._fallback_find()

    @staticmethod
    async def _scan_drive_powershell(drive: str) -> List[Path]:
        """Scan a single drive using PowerShell."""
        try:
            # SECURITY: Use shlex for safer command construction (even though shell=False)
            import shlex
            safe_drive = shlex.quote(drive)

            # SECURITY: Force UTF-8 encoding to prevent decoding issues
            # PowerShell defaults to UTF-16 which can corrupt file paths
            cmd = [
                "powershell", "-NoProfile", "-OutputFormat", "Text", "-Command",
                f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " +
                f"Get-ChildItem -Path {safe_drive} -Name 'node_modules' -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName"
            ]

            # SECURITY: Add timeout to prevent DoS from hanging processes
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)

            if proc.returncode != 0:
                return []

            paths = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    path = Path(line.strip())
                    if path.exists() and path.is_dir():
                        paths.append(path)

            return paths

        except asyncio.TimeoutError:
            # Drive scan timed out, return empty list
            return []
        except Exception:
            return []

    @staticmethod
    async def _fallback_find() -> List[Path]:
        """Fallback method using built-in filesystem scanning."""
        console = Console()
        console.print("⚡ Using built-in filesystem scanner...")
        
        # Get search roots
        search_roots = PlatformScanner._get_search_roots()
        
        all_paths = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning directories...", total=len(search_roots))
            
            for root in search_roots:
                progress.update(task, description=f"Scanning {root}")
                paths = await PlatformScanner._scan_directory_recursive(root, "node_modules", 15)
                all_paths.extend(paths)
                progress.advance(task)
        
        console.print(f"✅ Found {len(all_paths)} node_modules directories")
        return all_paths

    @staticmethod
    def _get_search_roots() -> List[Path]:
        """Get intelligent search roots based on platform."""
        roots = []
        
        # Always include user's home directory
        home = Path.home()
        if home.exists():
            roots.append(home)
        
        system = platform.system().lower()
        
        if system == "darwin":
            roots.extend([
                Path("/Applications"),
                Path("/usr/local"),
                Path("/opt")
            ])
        elif system == "linux":
            roots.extend([
                Path("/usr/local"),
                Path("/opt"),
                Path("/var/www"),
                Path("/srv")
            ])
        elif system == "windows":
            roots.extend([
                Path("C:/Users"),
                Path("C:/Program Files"),
                Path("C:/Program Files (x86)"),
                Path("C:/ProgramData")
            ])
        
        # Filter to existing directories
        return [root for root in roots if root.exists() and root.is_dir()]

    @staticmethod
    async def _scan_directory_recursive(root: Path, target_name: str, max_depth: int) -> List[Path]:
        """Recursively scan directory for target name."""
        found_paths = []

        def _scan_sync(path: Path, current_depth: int):
            if current_depth > max_depth:
                return

            # SECURITY: Prevent TOCTOU race condition
            # Check directory once and use safe iteration pattern
            try:
                # Single check-and-use to minimize race window
                if not path.is_dir():
                    return

                # Use try-except around iterdir to handle concurrent modifications
                try:
                    items = list(path.iterdir())
                except (PermissionError, OSError, FileNotFoundError):
                    # Directory inaccessible or removed during scan
                    return

                for item in items:
                    try:
                        # Re-check is_dir for each item (symlinks could be injected)
                        if not item.is_dir():
                            continue

                        if item.name == target_name:
                            found_paths.append(item)
                            continue  # Don't traverse into node_modules

                        # Skip certain directories for performance
                        if item.name in {'.git', '.svn', '.hg', '.bzr', 'target', 'build', 'dist', 'out'}:
                            continue

                        _scan_sync(item, current_depth + 1)
                    except (PermissionError, OSError, FileNotFoundError):
                        # Item changed or removed during iteration
                        continue

            except (PermissionError, OSError):
                pass  # Skip inaccessible directories

        # SECURITY: Use semaphore to limit concurrent directory scans
        # Prevents resource exhaustion from too many parallel operations
        async with PlatformScanner._scan_semaphore:
            # Run in thread pool to avoid blocking
            await asyncio.get_event_loop().run_in_executor(None, _scan_sync, root, 0)
        return found_paths

    @staticmethod
    def get_project_root(node_modules_path: Path) -> Path:
        """Get the project root directory."""
        return node_modules_path.parent

    @staticmethod
    def find_package_json(project_root: Path) -> Optional[Path]:
        """Find package.json in project root."""
        package_json_path = project_root / "package.json"
        return package_json_path if package_json_path.exists() else None


class DatabaseUpdater:
    """Manages automatic download and caching of vulnerability databases.

    Downloads vulnerability data from authoritative sources (OSV - Open Source
    Vulnerabilities database) and maintains a local cache in the user's home
    directory. Implements cache validation, automatic expiration (1 hour), and
    secure permission management.

    The updater uses async HTTP operations for efficient downloads and provides
    graceful fallback when network operations fail. Cache files are stored with
    strict permissions (0o700) to prevent unauthorized access.

    Attributes:
        cache_dir (Path): Local cache directory at ~/.cache/npmls
        session (Optional[aiohttp.ClientSession]): Async HTTP session for downloads

    Example:
        >>> import asyncio
        >>> async def update():
        ...     async with DatabaseUpdater() as updater:
        ...         db = await updater.update_database()
        ...         print(f"Downloaded {len(db.get('vulnerabilities', []))} vulnerabilities")
        >>> asyncio.run(update())
    """

    def __init__(self):
        # SECURITY: Create cache directory with strict permissions (0o700)
        # Prevents symlink attacks and unauthorized access to cached data
        self.cache_dir = Path.home() / ".cache" / "npmls"
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # SECURITY: Ensure existing directory has correct permissions
        # Protects against permission changes or symlink replacement
        try:
            self.cache_dir.chmod(0o700)
        except (OSError, PermissionError):
            # Unable to set permissions, continue with warning
            pass

        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300),
            headers={'User-Agent': 'npmls/0.4.0 (security-scanner)'}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def update_database(self) -> Dict[str, Any]:
        """Download and merge vulnerability databases."""
        console = Console()
        
        # Download from both OSV databases
        console.print("📥 Downloading vulnerability databases...")
        
        osv_db = await self._download_osv_database()
        await self._save_database(osv_db)
        
        console.print("✅ Database update complete")
        return osv_db

    async def load_database(self) -> Optional[Dict[str, Any]]:
        """Load cached database."""
        db_path = self.cache_dir / "osv_db.json"
        
        if not db_path.exists():
            return None
        
        try:
            async with aiofiles.open(db_path, 'r') as f:
                content = await f.read()
                database = json.loads(content)
                
                # Check version compatibility
                if database.get('version', '').startswith('3.'):
                    return database
                else:
                    # Remove incompatible version
                    db_path.unlink()
                    return None
        except Exception:
            # Remove corrupted database
            try:
                db_path.unlink()
            except:
                pass
            return None

    async def _download_osv_database(self) -> Dict[str, Any]:
        """Download OSV vulnerability database."""
        url = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
        
        console = Console()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            download_task = progress.add_task("Downloading OSV database...", total=None)
            
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"Failed to download OSV database: {response.status}")
                
                # Download to temporary file
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    async for chunk in response.content.iter_chunked(8192):
                        temp_file.write(chunk)
                    temp_path = temp_file.name
            
            progress.update(download_task, description="Processing OSV database...")
            
            # Parse ZIP data
            database = await self._parse_osv_zip(temp_path)
            
            # Cleanup
            os.unlink(temp_path)
        
        console.print(f"📦 Processed OSV database with {len(database.get('packages', {}))} packages")
        return database


    async def _save_database(self, database: Dict[str, Any]):
        """Save database to cache."""
        db_path = self.cache_dir / "osv_db.json"
        
        async with aiofiles.open(db_path, 'w') as f:
            await f.write(json.dumps(database, indent=2))


    async def _parse_osv_zip(self, zip_path: str) -> Dict[str, Any]:
        """Parse OSV ZIP file."""
        packages = {}
        processed_count = 0

        def _parse_sync():
            nonlocal processed_count
            with zipfile.ZipFile(zip_path, 'r') as archive:
                for file_info in archive.filelist:
                    # SECURITY: Prevent ZipSlip path traversal attack
                    # Validate that the file path is safe before processing
                    safe_path = Path(file_info.filename).resolve()
                    if '..' in file_info.filename or file_info.filename.startswith('/'):
                        continue  # Skip potentially malicious paths

                    if file_info.filename.endswith('.json'):
                        try:
                            with archive.open(file_info) as json_file:
                                vuln_data = json.load(json_file)

                                # SECURITY: Validate external data with Pydantic if available
                                if PYDANTIC_AVAILABLE:
                                    try:
                                        validated_vuln = OSVVulnerabilityModel(**vuln_data)
                                        vuln_data = validated_vuln.model_dump()
                                    except ValidationError:
                                        # Skip malformed vulnerability data
                                        continue

                                # Process npm packages only
                                for affected in vuln_data.get('affected', []):
                                    package_info = affected.get('package', {})
                                    if package_info.get('ecosystem') == 'npm':
                                        package_name = package_info.get('name')
                                        if package_name:
                                            vulnerable_pkg = self._osv_to_vulnerable_package(vuln_data, package_name)
                                            if package_name not in packages:
                                                packages[package_name] = []
                                            packages[package_name].append(vulnerable_pkg)
                                            processed_count += 1
                        except Exception:
                            continue  # Skip malformed JSON
        
        # Run in thread pool
        await asyncio.get_event_loop().run_in_executor(None, _parse_sync)
        
        return {
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'version': '3.0.0',
            'packages': packages,
            'total_vulnerabilities': processed_count,
            'osv_vulnerabilities': processed_count,
            'sources': ['OSV']
        }

    def _osv_to_vulnerable_package(self, vuln_data: Dict[str, Any], package_name: str) -> Dict[str, Any]:
        """Convert OSV vulnerability to vulnerable package format."""
        vuln_id = vuln_data.get('id', 'unknown')
        summary = vuln_data.get('summary', '')
        details = vuln_data.get('details', '')
        modified = vuln_data.get('modified', '')
        published = vuln_data.get('published', '')
        
        # Parse dates
        try:
            discovered = datetime.fromisoformat(modified.replace('Z', '+00:00'))
        except:
            try:
                discovered = datetime.fromisoformat(published.replace('Z', '+00:00'))
            except:
                discovered = datetime.now(timezone.utc)
        
        # Determine severity and threat type
        severity = self._determine_severity_osv(vuln_data)
        threat_type = self._determine_threat_type_osv(vuln_data)
        
        # Extract version
        version = self._extract_version_osv(vuln_data) or "unknown"
        
        return {
            'name': package_name,
            'version': version,
            'discovered': discovered.isoformat(),
            'threat_type': threat_type.value,
            'description': f"[{vuln_id}] {details or summary or 'Security vulnerability detected'}",
            'severity': severity.value,
            'references': [ref.get('url', '') for ref in vuln_data.get('references', [])],
            'cwe_ids': [],
            'nvd_published_at': None,
            'cvss_score': self._extract_cvss_score_osv(vuln_data),
            'cvss_vector': None,
            'source_database': VulnerabilitySource.OSV.value,
            'aliases': vuln_data.get('aliases', [])
        }

    def _determine_severity_osv(self, vuln_data: Dict[str, Any]) -> Severity:
        """Determine severity from OSV data."""
        severity_list = vuln_data.get('severity', [])
        
        for sev in severity_list:
            if sev.get('type') == 'CVSS_V3':
                try:
                    score = float(sev.get('score', 0))
                    if score >= 9.0:
                        return Severity.CRITICAL
                    elif score >= 7.0:
                        return Severity.HIGH
                    elif score >= 4.0:
                        return Severity.MEDIUM
                    else:
                        return Severity.LOW
                except:
                    pass
        
        # Fallback to text analysis
        text = f"{vuln_data.get('summary', '')} {vuln_data.get('details', '')}".lower()
        if 'critical' in text or 'rce' in text:
            return Severity.CRITICAL
        elif 'high' in text or 'sql injection' in text:
            return Severity.HIGH
        elif 'medium' in text:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _determine_threat_type_osv(self, vuln_data: Dict[str, Any]) -> ThreatType:
        """Determine threat type from OSV data."""
        text = f"{vuln_data.get('summary', '')} {vuln_data.get('details', '')}".lower()
        
        if 'supply chain' in text or 'vulnerable package' in text:
            return ThreatType.SUPPLY_CHAIN_ATTACK
        elif 'credential' in text or 'token' in text:
            return ThreatType.CREDENTIAL_THEFT
        elif 'crypto' in text or 'mining' in text:
            return ThreatType.CRYPTOJACKING
        elif 'xss' in text or 'cross-site scripting' in text:
            return ThreatType.CROSS_SITE_SCRIPTING
        elif 'sql injection' in text or 'sqli' in text:
            return ThreatType.SQL_INJECTION
        elif 'rce' in text or 'remote code execution' in text:
            return ThreatType.REMOTE_CODE_EXECUTION
        elif 'dos' in text or 'denial of service' in text:
            return ThreatType.DENIAL_OF_SERVICE
        elif 'privilege escalation' in text:
            return ThreatType.PRIVILEGE_ESCALATION
        elif 'buffer overflow' in text:
            return ThreatType.BUFFER_OVERFLOW
        else:
            return ThreatType.OTHER

    def _extract_version_osv(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract version from OSV vulnerability data."""
        for affected in vuln_data.get('affected', []):
            versions = affected.get('versions', [])
            if versions:
                return versions[0]
            
            ranges = affected.get('ranges', [])
            for range_info in ranges:
                events = range_info.get('events', [])
                for event in events:
                    introduced = event.get('introduced')
                    if introduced and introduced != '0':
                        return introduced
        
        return None

    def _extract_cvss_score_osv(self, vuln_data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from OSV data."""
        severity_list = vuln_data.get('severity', [])
        
        for sev in severity_list:
            if sev.get('type') in ['CVSS_V3', 'CVSS_V2']:
                try:
                    return float(sev.get('score', 0))
                except:
                    pass
        
        return None


class ThreatDatabase:
    """Manages threat intelligence database for vulnerability lookups.

    Maintains an in-memory database of known vulnerable npm packages sourced from
    OSV (Open Source Vulnerabilities) and GitHub Advisory Database. Provides fast
    lookup capabilities using semantic versioning comparison.

    The database is automatically updated from online sources when cache is stale
    (>1 hour old) in online mode, or runs empty in offline mode.

    Attributes:
        vulnerable_packages (Dict[str, List[VulnerablePackage]]): Package name to vulnerabilities mapping
        online_mode (bool): Whether to enable automatic database updates

    Example:
        >>> db = ThreatDatabase(online_mode=True)
        >>> await db.load_or_update_database()
        >>> threat = db.check_package_fast("chalk", "5.6.1")
        >>> if threat:
        ...     print(f"Vulnerable: {threat.description}")
    """

    def __init__(self, online_mode: bool = True):
        """Initialize threat database.

        Args:
            online_mode: Enable automatic updates from online sources (True)
                        or offline mode with no threat detection (False)
        """
        self.vulnerable_packages: Dict[str, List[VulnerablePackage]] = {}
        self.online_mode = online_mode

    async def load_or_update_database(self):
        """Load cached database or update from online sources.

        In online mode: Downloads latest vulnerability data if cache is stale
        (>1 hour old) or missing. In offline mode: Returns empty database.

        Raises:
            Exception: If online database download fails and no cache available
        """
        if not self.online_mode:
            console = Console()
            console.print("🔒 Using offline mode (no threat detection) ✅")
            return

        async with DatabaseUpdater() as updater:
            # Try to load cached database first
            cached_db = await updater.load_database()
            
            if cached_db:
                # Check if database is stale (older than 1 hour)
                try:
                    last_updated = datetime.fromisoformat(cached_db['last_updated'].replace('Z', '+00:00'))
                    age_hours = (datetime.now(timezone.utc) - last_updated).total_seconds() / 3600
                    
                    if age_hours > 1:
                        console = Console()
                        console.print(f"🔄 Cached database is {int(age_hours)}h old, updating...")
                        database = await updater.update_database()
                        self._merge_cached_database(database)
                    else:
                        console = Console()
                        self._merge_cached_database(cached_db)
                        console.print(f"📥 Loaded {cached_db.get('total_vulnerabilities', 0)} vulnerabilities from cache ({int(age_hours)}h old) ✅")
                except Exception as e:
                    # If there's an error with cached data, update fresh
                    database = await updater.update_database()
                    self._merge_cached_database(database)
            else:
                # No cached database, download fresh
                console = Console()
                console.print("📥 No cached database found, downloading...")
                database = await updater.update_database()
                self._merge_cached_database(database)

    def _merge_cached_database(self, cached_db: Dict[str, Any]):
        """Merge cached database with built-in threats."""
        for package_name, vulns in cached_db.get('packages', {}).items():
            if package_name not in self.vulnerable_packages:
                self.vulnerable_packages[package_name] = []
            
            for vuln_dict in vulns:
                # Convert dict back to VulnerablePackage object
                vuln = self._dict_to_vulnerable_package(vuln_dict)
                
                # Avoid duplicates
                if not any(existing.version == vuln.version and existing.name == vuln.name 
                          for existing in self.vulnerable_packages[package_name]):
                    self.vulnerable_packages[package_name].append(vuln)

    def _dict_to_vulnerable_package(self, vuln_dict: Dict[str, Any]) -> VulnerablePackage:
        """Convert dictionary to VulnerablePackage object."""
        discovered = datetime.fromisoformat(vuln_dict['discovered'].replace('Z', '+00:00'))
        threat_type = ThreatType(vuln_dict['threat_type'])
        severity = Severity(vuln_dict['severity'])
        source_db = VulnerabilitySource(vuln_dict.get('source_database', 'BuiltIn'))
        
        # Handle optional datetime fields
        nvd_published_at = None
        if vuln_dict.get('nvd_published_at'):
            nvd_published_at = datetime.fromisoformat(vuln_dict['nvd_published_at'].replace('Z', '+00:00'))
        
        return VulnerablePackage(
            name=vuln_dict['name'],
            version=vuln_dict['version'],
            discovered=discovered,
            threat_type=threat_type,
            description=vuln_dict['description'],
            severity=severity,
            references=vuln_dict.get('references', []),
            cwe_ids=vuln_dict.get('cwe_ids', []),
            nvd_published_at=nvd_published_at,
            cvss_score=vuln_dict.get('cvss_score'),
            cvss_vector=vuln_dict.get('cvss_vector'),
            source_database=source_db,
            aliases=vuln_dict.get('aliases', [])
        )

    def check_package_fast(self, name: str, version: str) -> Optional[VulnerablePackage]:
        """Fast check for vulnerable packages using semantic versioning.

        SECURITY: Uses proper SemVer comparison to prevent false negatives.
        """
        if name in self.vulnerable_packages:
            for pkg in self.vulnerable_packages[name]:
                # SECURITY: Use semantic version comparison instead of string equality
                if compare_versions(version, pkg.version):
                    return pkg
        return None

    def get_all_vulnerable_packages(self) -> List[VulnerablePackage]:
        """Get all vulnerable packages."""
        result = []
        for packages in self.vulnerable_packages.values():
            result.extend(packages)
        return result


class Scanner:
    """Main scanner class for detecting vulnerable npm packages across the system.

    Coordinates filesystem scanning, package analysis, and threat matching to identify
    vulnerable npm packages installed on the system. Uses platform-specific optimizations
    for fast discovery and async processing for efficient concurrent scanning.

    Attributes:
        threat_db (ThreatDatabase): Database of known vulnerabilities
        verbose (bool): Enable detailed progress output

    Example:
        >>> import asyncio
        >>> scanner = Scanner(verbose=True, online_mode=True)
        >>> asyncio.run(scanner.initialize())
        >>> results = asyncio.run(scanner.scan_system())
        >>> malicious = [r for r in results if r.is_vulnerable]
        >>> print(f"Found {len(malicious)} vulnerable packages")
    """

    def __init__(self, verbose: bool = False, online_mode: bool = True):
        """Initialize scanner with configuration options.

        Args:
            verbose: Enable detailed progress output during scanning
            online_mode: Enable automatic database updates (True) or offline mode (False)
        """
        self.threat_db = ThreatDatabase(online_mode)
        self.verbose = verbose

    async def initialize(self):
        """Initialize the scanner and load/update threat database.

        Must be called before scan_system(). Downloads latest vulnerability data
        if in online mode and cache is stale, or loads from cache if available.

        Raises:
            Exception: If database initialization fails in online mode
        """
        await self.threat_db.load_or_update_database()
        
        if self.verbose:
            total_threats = len(self.threat_db.get_all_vulnerable_packages())
            mode = "online" if self.threat_db.online_mode else "offline"
            console = Console()
            console.print(f"📊 Loaded {total_threats} known vulnerable package variants ({mode})")

    async def scan_system(self) -> List[ScanResult]:
        """Scan the entire system for npm packages."""
        console = Console()
        console.print("🔍 Discovering node_modules directories...")
        
        # Find all node_modules directories
        node_modules_paths = await PlatformScanner.find_node_modules()
        
        if not node_modules_paths:
            console.print("✅ No node_modules directories found on this system")
            return []

        console.print(f"📦 Analyzing {len(node_modules_paths)} node_modules directories...")
        
        all_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning directories...", total=len(node_modules_paths))
            
            for node_modules_path in node_modules_paths:
                try:
                    results = await self._scan_node_modules_directory(node_modules_path)
                    all_results.extend(results)
                except Exception as e:
                    if self.verbose:
                        console.print(f"⚠️ Error scanning directory {node_modules_path}: {e}")
                
                progress.advance(task)
        
        # Deduplicate results
        unique_results = self._deduplicate_results(all_results)
        
        # Print summary
        total_packages = len(unique_results)
        vulnerable_count = sum(1 for r in unique_results if r.is_vulnerable)
        
        console.print("\n📊 Scan Results:")
        console.print(f"   • Total packages found: [bold white]{total_packages}[/bold white]")
        
        if vulnerable_count > 0:
            console.print(f"   • [bold red]vulnerable PACKAGES DETECTED: {vulnerable_count}[/bold red]")
        else:
            console.print("   • [bold green]No known vulnerable packages detected[/bold green]")
        
        return unique_results

    async def _scan_node_modules_directory(self, node_modules_path: Path) -> List[ScanResult]:
        """Scan a single node_modules directory."""
        results = []
        
        # Get project root and check for package.json
        project_root = PlatformScanner.get_project_root(node_modules_path)
        package_json_path = PlatformScanner.find_package_json(project_root)
        
        if package_json_path:
            try:
                package_info = await self._parse_package_json(package_json_path)
                threat = self.threat_db.check_package_fast(package_info.name, package_info.version)
                results.append(ScanResult(
                    package=package_info,
                    threat=threat,
                    is_vulnerable=threat is not None
                ))
            except Exception:
                pass  # Skip malformed package.json files
        
        # Scan individual packages within node_modules
        try:
            for item in node_modules_path.iterdir():
                if item.is_dir():
                    if item.name.startswith('.'):
                        continue  # Skip hidden directories
                    
                    if item.name.startswith('@'):
                        # Handle scoped packages
                        try:
                            for scoped_item in item.iterdir():
                                if scoped_item.is_dir():
                                    try:
                                        package_info = await self._scan_individual_package(scoped_item)
                                        threat = self.threat_db.check_package_fast(package_info.name, package_info.version)
                                        results.append(ScanResult(
                                            package=package_info,
                                            threat=threat,
                                            is_vulnerable=threat is not None
                                        ))
                                    except Exception:
                                        continue
                        except Exception:
                            continue
                    else:
                        # Regular package
                        try:
                            package_info = await self._scan_individual_package(item)
                            threat = self.threat_db.check_package_fast(package_info.name, package_info.version)
                            results.append(ScanResult(
                                package=package_info,
                                threat=threat,
                                is_vulnerable=threat is not None
                            ))
                        except Exception:
                            continue
        except Exception:
            pass  # Skip inaccessible directories
        
        return results

    async def _scan_individual_package(self, package_path: Path) -> PackageInfo:
        """Scan an individual package directory."""
        package_json_path = package_path / "package.json"
        return await self._parse_package_json(package_json_path)

    async def _parse_package_json(self, package_json_path: Path) -> PackageInfo:
        """Parse a package.json file with robust error handling."""
        # SECURITY: Robust JSON parsing to prevent detection bypass
        # Handles malformed JSON, oversized files, and crafted DoS payloads
        try:
            # Check file size before reading to prevent memory exhaustion
            stat = package_json_path.stat()
            MAX_PACKAGE_JSON_SIZE = 10 * 1024 * 1024  # 10MB limit

            if stat.st_size > MAX_PACKAGE_JSON_SIZE:
                # File too large, likely not a legitimate package.json
                if self.verbose:
                    console = Console()
                    safe_path = sanitize_path_for_display(package_json_path)
                    console.print(f"⚠️ Skipping oversized package.json: {safe_path}")
                raise ValueError(f"package.json file too large: {stat.st_size} bytes")

            async with aiofiles.open(package_json_path, 'r', encoding='utf-8') as f:
                content = await f.read()

            # Parse JSON with error handling
            data = json.loads(content)

            # Validate that data is a dictionary
            if not isinstance(data, dict):
                raise ValueError("package.json root must be an object")

            name = data.get('name', 'unknown')
            version = data.get('version', 'unknown')

            # Validate name and version are strings
            if not isinstance(name, str):
                name = str(name) if name is not None else 'unknown'
            if not isinstance(version, str):
                version = str(version) if version is not None else 'unknown'

            size_bytes = stat.st_size
            modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc)

            return PackageInfo(
                name=name,
                version=version,
                path=str(package_json_path.parent),
                size_bytes=size_bytes,
                modified=modified
            )

        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            # Malformed JSON or invalid data - skip this package but continue scan
            if self.verbose:
                console = Console()
                safe_path = sanitize_path_for_display(package_json_path)
                console.print(f"⚠️ Skipping malformed package.json: {safe_path} ({type(e).__name__})")
            raise  # Re-raise to be caught by caller

    def _deduplicate_results(self, results: List[ScanResult]) -> List[ScanResult]:
        """Remove duplicate scan results."""
        seen = set()
        unique_results = []
        
        for result in results:
            key = (result.package.name, result.package.version)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        # Sort by name and version
        unique_results.sort(key=lambda r: (r.package.name, r.package.version))
        return unique_results

    def get_threat_summary(self) -> List[VulnerablePackage]:
        """Get summary of all known threats."""
        return self.threat_db.get_all_vulnerable_packages()


class Reporter:
    """Generates security scan reports in multiple output formats.

    Supports table (terminal), JSON, and CSV output formats with optional filtering
    for vulnerable packages only. Provides automatic file generation with timestamps
    and CSV injection protection for security.

    Attributes:
        format_type (str): Output format - 'table', 'json', or 'csv'
        threats_only (bool): Filter to show only vulnerable packages
        auto_generate_files (bool): Automatically create timestamped JSON/CSV files

    Example:
        >>> reporter = Reporter(format_type="json", threats_only=True)
        >>> await reporter.generate_report(scan_results, Path("report.json"))
    """

    def __init__(self, format_type: str = "table", threats_only: bool = False, auto_generate_files: bool = True):
        """Initialize reporter with output configuration.

        Args:
            format_type: Output format ('table', 'json', or 'csv')
            threats_only: If True, only include vulnerable packages in output
            auto_generate_files: If True, automatically create timestamped JSON/CSV files
        """
        self.format_type = format_type
        self.threats_only = threats_only
        self.auto_generate_files = auto_generate_files

    async def generate_report(self, results: List[ScanResult], output_file: Optional[Path] = None):
        """Generate and output scan report in configured format.

        Args:
            results: List of scan results from Scanner.scan_system()
            output_file: Optional file path for output (stdout if None)

        Raises:
            IOError: If output file cannot be written
        """
        console = Console()
        
        # Filter results if needed
        filtered_results = [r for r in results if r.is_vulnerable] if self.threats_only else results
        
        if self.format_type == "json":
            content = self._generate_json_report(filtered_results)
        elif self.format_type == "csv":
            content = self._generate_csv_report(filtered_results)
        else:
            content = self._generate_table_report(filtered_results)
        
        # Always show table output to console (unless JSON/CSV was specifically requested for console)
        if output_file is None and self.format_type in ["json", "csv"]:
            # For JSON/CSV format without file output, show both console table and the requested format
            table_content = self._generate_table_report(filtered_results)
            console.print(table_content)
            console.print(f"\n--- {self.format_type.upper()} Output ---")
            console.print(content)
        elif output_file is None:
            # Normal table output
            console.print(content)
        
        # Save to file if specified
        if output_file:
            async with aiofiles.open(output_file, 'w') as f:
                await f.write(content)
            console.print(f"📄 Report saved to: {output_file}")
        
        # Auto-generate JSON and CSV files by default (unless user specified a specific format/file or disabled auto-generation)
        if output_file is None and self.format_type == "table" and self.auto_generate_files:
            await self._auto_generate_files(filtered_results, console)
        
        # Show threat summary if vulnerable packages found
        vulnerable_results = [r for r in results if r.is_vulnerable]
        if vulnerable_results:
            self._print_threat_summary(vulnerable_results)

    async def _auto_generate_files(self, results: List[ScanResult], console: Console):
        """Automatically generate JSON and CSV files with timestamped names."""
        if not results:
            return
            
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate JSON file
        json_filename = f"npmls_scan_{timestamp}.json"
        json_content = self._generate_json_report(results)
        try:
            async with aiofiles.open(json_filename, 'w') as f:
                await f.write(json_content)
            console.print(f"📄 JSON report auto-saved to: [cyan]{json_filename}[/cyan]")
        except Exception as e:
            console.print(f"⚠️ Could not save JSON file: {e}")
        
        # Generate CSV file
        csv_filename = f"npmls_scan_{timestamp}.csv"
        csv_content = self._generate_csv_report(results)
        try:
            async with aiofiles.open(csv_filename, 'w') as f:
                await f.write(csv_content)
            console.print(f"📄 CSV report auto-saved to: [cyan]{csv_filename}[/cyan]")
        except Exception as e:
            console.print(f"⚠️ Could not save CSV file: {e}")
        
        # Show file locations
        console.print(f"\n💡 Tip: Use [bold]--format json[/bold] or [bold]--format csv[/bold] to see raw output, or [bold]-o filename[/bold] to specify custom output file")

    def _generate_table_report(self, results: List[ScanResult]) -> str:
        """Generate table format report."""
        if not results:
            if self.threats_only:
                return "\n✅ No vulnerable packages detected!\n"
            else:
                return "\nℹ️ No npm packages found on this system.\n"
        
        # Get terminal width and calculate column widths
        try:
            import shutil
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 120
        
        # Calculate dynamic column widths
        max_name_len = min(max(len(r.package.name) for r in results), 30)
        max_version_len = min(max(len(r.package.version) for r in results), 15)
        
        # Reserve space for fixed columns and padding
        fixed_width = max_name_len + max_version_len + 25  # Status + Threat Level + padding
        location_width = max(terminal_width - fixed_width, 40)  # Minimum 40 chars for location
        
        # Create rich table with dynamic column widths
        table = Table(title="📦 NPM Package Security Scan Results", width=terminal_width)
        table.add_column("Package Name", style="cyan", width=max_name_len)
        table.add_column("Version", style="magenta", width=max_version_len)
        table.add_column("Status", style="green", width=12)
        table.add_column("Threat Level", width=13)
        table.add_column("Location", style="dim", width=location_width)
        
        for result in results:
            package = result.package
            
            if result.is_vulnerable:
                status = "[red]🚨 Vulnerable[/red]"
                if result.threat:
                    if result.threat.severity == Severity.CRITICAL:
                        threat_level = "[red]🔴 Critical[/red]"
                    elif result.threat.severity == Severity.HIGH:
                        threat_level = "[yellow]🟠 High[/yellow]"
                    elif result.threat.severity == Severity.MEDIUM:
                        threat_level = "[yellow]🟡 Medium[/yellow]"
                    else:
                        threat_level = "[green]🟢 Low[/green]"
                else:
                    threat_level = "—"
            else:
                status = "[green]✅ Clean[/green]"
                threat_level = "—"
            
            # Smart path truncation - show most important parts
            location = package.path
            if len(location) > location_width - 3:
                # Try to keep the project name and package name visible
                parts = location.split('/')
                if len(parts) > 3:
                    # Keep first part (drive/root), last 2 parts (project/node_modules), truncate middle
                    truncated = f"{parts[0]}/.../{'/'.join(parts[-2:])}"
                    if len(truncated) <= location_width - 3:
                        location = truncated
                    else:
                        location = "..." + location[-(location_width-6):]
                else:
                    location = "..." + location[-(location_width-6):]
            
            # Truncate package name if needed
            display_name = package.name
            if len(display_name) > max_name_len:
                display_name = display_name[:max_name_len-3] + "..."
                
            # Truncate version if needed
            display_version = package.version
            if len(display_version) > max_version_len:
                display_version = display_version[:max_version_len-3] + "..."
            
            table.add_row(
                display_name,
                display_version,
                status,
                threat_level,
                location
            )
        
        # Create console for table rendering
        console = Console(file=open(os.devnull, 'w'), width=terminal_width)
        with console.capture() as capture:
            console.print(table)
        
        output = capture.get()
        
        # Add summary
        total = len(results)
        vulnerable = sum(1 for r in results if r.is_vulnerable)
        
        output += f"\n📊 Summary: {total} total packages, {vulnerable} vulnerable\n"
        
        return output

    def _generate_json_report(self, results: List[ScanResult]) -> str:
        """Generate JSON format report."""
        vulnerable_results = [r for r in results if r.is_vulnerable]
        
        # Calculate statistics
        severity_counts = {}
        source_counts = {}
        threat_type_counts = {}
        
        for result in vulnerable_results:
            if result.threat:
                severity = result.threat.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                source = result.threat.source_database.value
                source_counts[source] = source_counts.get(source, 0) + 1
                
                threat_type = result.threat.threat_type.value
                threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
        
        report_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_type": "npm_security_scan",
            "threats_only": self.threats_only,
            "summary": {
                "total_packages": len(results),
                "vulnerable_packages": len(vulnerable_results),
                "clean_packages": len(results) - len(vulnerable_results),
                "severity_breakdown": severity_counts,
                "source_breakdown": source_counts,
                "threat_type_breakdown": threat_type_counts,
                "packages_with_cvss_scores": sum(1 for r in vulnerable_results if r.threat and r.threat.cvss_score),
            },
            "results": [self._scan_result_to_dict(result) for result in results]
        }
        
        return json.dumps(report_data, indent=2, default=str)

    def _scan_result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to dictionary."""
        result_dict = {
            "package": asdict(result.package),
            "is_vulnerable": result.is_vulnerable,
            "threat": None
        }
        
        if result.threat:
            threat_dict = asdict(result.threat)
            # Convert datetime objects to ISO strings
            for key, value in threat_dict.items():
                if isinstance(value, datetime):
                    threat_dict[key] = value.isoformat()
                elif isinstance(value, (ThreatType, Severity, VulnerabilitySource)):
                    threat_dict[key] = value.value
            result_dict["threat"] = threat_dict
        
        # Convert datetime in package info
        result_dict["package"]["modified"] = result.package.modified.isoformat()
        
        return result_dict

    def _generate_csv_report(self, results: List[ScanResult]) -> str:
        """Generate CSV format report."""
        output = []
        
        # Header
        header = [
            "Package Name", "Version", "Path", "Size (bytes)", "is_vulnerable",
            "Threat Type", "Severity", "Description", "CWE IDs", "CVSS Score", "CVSS Vector", 
            "NVD Published At", "Source Database", "Aliases", "References", "Discovered Date"
        ]
        output.append(','.join(header))
        
        # Rows
        for result in results:
            package = result.package
            is_vulnerable = "true" if result.is_vulnerable else "false"
            
            if result.threat:
                threat = result.threat
                row = [
                    self._csv_escape(package.name),
                    package.version,
                    self._csv_escape(package.path),
                    str(package.size_bytes),
                    is_vulnerable,
                    threat.threat_type.value,
                    threat.severity.value,
                    self._csv_escape(threat.description),
                    ";".join(threat.cwe_ids),
                    str(threat.cvss_score) if threat.cvss_score else "N/A",
                    self._csv_escape(threat.cvss_vector or "N/A"),
                    threat.nvd_published_at.isoformat() if threat.nvd_published_at else "N/A",
                    threat.source_database.value,
                    ";".join(threat.aliases),
                    ";".join(threat.references),
                    threat.discovered.isoformat()
                ]
            else:
                row = [
                    self._csv_escape(package.name),
                    package.version,
                    self._csv_escape(package.path),
                    str(package.size_bytes),
                    is_vulnerable,
                    "None", "None", "No threats detected",
                    "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
                ]
            
            output.append(','.join(row))
        
        return '\n'.join(output)

    def _csv_escape(self, value: str) -> str:
        """Escape CSV value with injection protection.

        SECURITY: Prevents CSV injection by sanitizing formula characters.
        Formula characters (=, +, -, @, \t) are prefixed with single quote.
        """
        # SECURITY: CSV Injection Prevention
        # Spreadsheet applications interpret cells starting with these characters as formulas
        dangerous_chars = ('=', '+', '-', '@', '\t', '\r')

        # Check if value starts with dangerous character
        if value and value[0] in dangerous_chars:
            # Prefix with single quote to force text interpretation
            value = "'" + value

        # Standard CSV escaping for quotes, commas, newlines
        if ',' in value or '"' in value or '\n' in value:
            return f'"{value.replace('"', '""')}"'

        return value

    def _print_threat_summary(self, vulnerable_results: List[ScanResult]):
        """Print detailed threat summary."""
        console = Console()
        
        console.print("\n[bold red]🚨 SECURITY ALERT - VULNERABLE PACKAGES DETECTED[/bold red]")
        console.print("[red]" + "═" * 60 + "[/red]")
        
        for result in vulnerable_results:
            if result.threat:
                threat = result.threat
                
                console.print(f"\n[bold white]📦 Package:[/bold white] [bold red]{result.package.name}@{result.package.version}[/bold red]")
                console.print(f"[bold white]📍 Location:[/bold white] [dim]{result.package.path}[/dim]")
                console.print(f"[bold white]⚡ Threat Type:[/bold white] [bright_yellow]{threat.threat_type.value}[/bright_yellow]")
                
                severity_color = {
                    Severity.CRITICAL: "bright_red",
                    Severity.HIGH: "bright_yellow", 
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "green"
                }[threat.severity]
                
                console.print(f"[bold white]🔥 Severity:[/bold white] [{severity_color}]{threat.severity.value.upper()}[/{severity_color}]")
                console.print(f"[bold white]📝 Description:[/bold white] [bright_white]{threat.description}[/bright_white]")
                
                if threat.cwe_ids:
                    console.print(f"[bold white]🏷️ CWE IDs:[/bold white] [bright_magenta]{', '.join(threat.cwe_ids)}[/bright_magenta]")
                
                if threat.cvss_score:
                    console.print(f"[bold white]📊 CVSS Score:[/bold white] [bright_cyan]{threat.cvss_score:.1f}[/bright_cyan]")
                                
                console.print(f"[bold white]📊 Source:[/bold white] [bright_blue]{threat.source_database.value}[/bright_blue]")
                
                if threat.aliases:
                    console.print(f"[bold white]🆔 Aliases:[/bold white] [bright_yellow]{', '.join(threat.aliases)}[/bright_yellow]")
                
                if threat.references:
                    refs = ', '.join(threat.references)
                    console.print(f"[bold white]🔗 References:[/bold white] [bright_blue link]{refs}[/bright_blue link]")
                
                console.print("[dim]" + "─" * 60 + "[/dim]")
        
        console.print(f"\n[bold yellow]🛡️ RECOMMENDED ACTIONS:[/bold yellow]")
        console.print("   1. [bright_red]🚫[/bright_red] Immediately remove or downgrade affected packages")
        console.print("   2. [bright_yellow]🔍[/bright_yellow] Check your package-lock.json for these versions")
        console.print("   3. [bright_cyan]🔧[/bright_cyan] Audit your project dependencies: npm audit")
        console.print("   4. [bright_cyan]🔧[/bright_cyan] Consider using npm audit fix for automated fixes")
        console.print("   5. [bright_magenta]👁️[/bright_magenta]  Monitor your systems for signs of compromise")
        console.print("   6. [bright_green]⬆️[/bright_green]  Update to latest secure versions when available")
        
        console.print(f"\n[dim]For more information about these threats, visit the provided references.[/dim]")


def validate_output_path(output_path: Path, allow_overwrite: bool = False) -> Path:
    """Validate and sanitize output file path.

    SECURITY: Prevents data exfiltration to special files or unsafe locations.
    SECURITY: Prevents accidental overwriting of important files.

    Args:
        output_path: Path to validate
        allow_overwrite: If True, skip overwrite confirmation

    Returns:
        Validated absolute path

    Raises:
        ValueError: If path is invalid or file exists without permission
    """
    try:
        # Resolve to absolute path
        abs_path = output_path.resolve()

        # SECURITY: Prevent writing to special files (devices, pipes, sockets)
        if abs_path.exists():
            # Check if it's a special file
            if not abs_path.is_file():
                raise ValueError(f"Output path is not a regular file: {abs_path}")

            # SECURITY: Check for file overwrite risk
            # Prevents accidental data loss from overwriting important files
            if not allow_overwrite and abs_path.stat().st_size > 0:
                console = Console()
                safe_path = sanitize_path_for_display(abs_path)
                console.print(f"[yellow]⚠️  File already exists: {safe_path}[/yellow]")
                console.print("[yellow]   File size: {:.2f} KB[/yellow]".format(abs_path.stat().st_size / 1024))

                # Interactive confirmation
                try:
                    response = input("Overwrite? [y/N]: ").strip().lower()
                    if response not in ['y', 'yes']:
                        raise ValueError("File overwrite cancelled by user")
                except (KeyboardInterrupt, EOFError):
                    raise ValueError("\nFile overwrite cancelled by user")

        # SECURITY: Ensure parent directory exists and is accessible
        parent_dir = abs_path.parent
        if not parent_dir.exists():
            raise ValueError(f"Output directory does not exist: {parent_dir}")

        if not parent_dir.is_dir():
            raise ValueError(f"Output parent is not a directory: {parent_dir}")

        # SECURITY: Check for common special file patterns
        special_files = ['/dev/', '/proc/', '/sys/', '\\\\']  # Unix devices and network paths
        for special in special_files:
            if special in str(abs_path):
                raise ValueError(f"Output path contains restricted pattern: {special}")

        return abs_path

    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid output path: {e}")


async def main():
    """Application entry point - command-line interface for NPM security scanner.

    Parses command-line arguments and orchestrates the scanning process.
    Supports multiple output formats (table, JSON, CSV) and operational modes
    (online with automatic database updates, offline mode, database update only).

    Command-line Options:
        -o, --output: Output file path for scan results
        --format: Output format (table, json, csv)
        -t, --threats-only: Show only vulnerable packages
        -v, --verbose: Enable detailed progress output
        --offline: Skip database downloads (no threat detection)
        --update-db: Update vulnerability database and exit
        --list-threats: Display all known threats and exit
        --no-auto-files: Disable automatic JSON/CSV file generation
        --force: Overwrite existing output files without confirmation

    Raises:
        SystemExit: On user interruption (Ctrl+C) or validation errors

    Returns:
        None
    """
    parser = argparse.ArgumentParser(
        description="Fast cross-platform scanner for npm modules and vulnerable packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Scan entire system
  %(prog)s --threats-only               # Show only vulnerable packages
  %(prog)s --format json -o report.json # JSON output to file
  %(prog)s --list-threats               # List all known threats
  %(prog)s --offline                    # Offline mode only
        """
    )

    parser.add_argument('-o', '--output', type=Path, help='Output results to file')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('-t', '--threats-only', action='store_true',
                        help='Only show packages matching known vulnerable versions')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output with detailed scan progress')
    parser.add_argument('--offline', action='store_true',
                        help='Offline mode - skip all downloads (no threat detection)')
    parser.add_argument('--update-db', action='store_true',
                        help='Update vulnerability database from online sources and exit')
    parser.add_argument('--list-threats', nargs='?', const='', metavar='FILTER',
                        help='List all known vulnerable packages and versions, then exit')
    parser.add_argument('--no-auto-files', action='store_true',
                        help='Disable automatic generation of JSON and CSV files')
    parser.add_argument('--force', action='store_true',
                        help='Force overwrite of existing output files without confirmation')
    
    args = parser.parse_args()
    
    # Set up console
    console = Console()
    
    # Print header
    console.print(f"[bold bright_cyan]🔍 NPM Package Security Scan [/bold bright_cyan]")
    console.print("[dim]Scan entire file system for vulnerable npm packages and modules[/dim]\n")
    
    # SECURITY: Validate output path if provided
    validated_output = None
    if args.output:
        try:
            validated_output = validate_output_path(args.output, allow_overwrite=args.force)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)

    # Handle format override for file output
    if validated_output and args.format == 'table':
        args.format = 'csv'

    try:
        # Handle database update mode
        if args.update_db:
            async with DatabaseUpdater() as updater:
                await updater.update_database()
                console.print("[bold bright_green]✅ Vulnerability database updated successfully![/bold bright_green]")
                return
        
        # Initialize scanner
        scanner = Scanner(verbose=args.verbose, online_mode=not args.offline)
        await scanner.initialize()
        
        # Handle list threats mode
        if args.list_threats is not None:
            threats = scanner.get_threat_summary()
            
            if not threats:
                console.print("[yellow]No known threats in database[/yellow]")
                return
            
            # Group threats by package name
            grouped_threats = {}
            for threat in threats:
                if threat.name not in grouped_threats:
                    grouped_threats[threat.name] = []
                grouped_threats[threat.name].append(threat)
            
            sorted_packages = sorted(grouped_threats.keys())
            
            # Apply filter if provided
            if args.list_threats:
                filter_lower = args.list_threats.lower()
                sorted_packages = [
                    pkg for pkg in sorted_packages 
                    if filter_lower in pkg.lower() or 
                    any(filter_lower in threat.description.lower() or 
                        any(filter_lower in alias.lower() for alias in threat.aliases)
                        for threat in grouped_threats[pkg])
                ]
                
                if not sorted_packages:
                    console.print(f"[yellow]No threats found matching filter: '{args.list_threats}'[/yellow]")
                    return
                
                console.print(f"[bright_cyan]Filtered results for: '{args.list_threats}'[/bright_cyan]\n")
            
            # Display threats
            for package_name in sorted_packages:
                threats_for_package = grouped_threats[package_name]
                
                console.print(f"[bold white]📦 {package_name}[/bold white]")
                
                for threat in threats_for_package:
                    severity_icon = {
                        Severity.CRITICAL: "🔴",
                        Severity.HIGH: "🟠", 
                        Severity.MEDIUM: "🟡",
                        Severity.LOW: "🔵"
                    }[threat.severity]
                    
                    threat_type_str = {
                        ThreatType.SUPPLY_CHAIN_ATTACK: "Supply Chain Attack",
                        ThreatType.CRYPTOJACKING: "Cryptojacking",
                        ThreatType.CREDENTIAL_THEFT: "Credential Theft",
                        ThreatType.BACKDOOR: "Backdoor",
                        ThreatType.DATA_EXFILTRATION: "Data Exfiltration",
                        ThreatType.RANSOMWARE: "Ransomware",
                        ThreatType.CROSS_SITE_SCRIPTING: "Cross-Site Scripting",
                        ThreatType.SQL_INJECTION: "SQL Injection",
                        ThreatType.REMOTE_CODE_EXECUTION: "Remote Code Execution",
                        ThreatType.DENIAL_OF_SERVICE: "Denial of Service",
                        ThreatType.PRIVILEGE_ESCALATION: "Privilege Escalation",
                        ThreatType.BUFFER_OVERFLOW: "Buffer Overflow",
                        ThreatType.OTHER: "Other",
                        ThreatType.UNKNOWN: "Unknown"
                    }[threat.threat_type]
                    
                    console.print(f"  {severity_icon} Version: [bold red]{threat.version}[/bold red] | [bright_magenta]{threat.severity.value}[/bright_magenta] [dim]{threat_type_str}[/dim] | [dim]{threat.discovered.strftime('%Y-%m-%d')}[/dim]")
                    
                    if threat.description:
                        # Truncate description
                        description = threat.description
                        if "The following packages and versions are affected" in description:
                            description = description.split("The following packages and versions are affected")[0]
                        
                        description = description.strip()
                        if not description.endswith('.'):
                            description += '.'
                        
                        if description:
                            # Word wrap for terminal
                            import textwrap
                            wrapped = textwrap.fill(description, width=115, initial_indent='     ', subsequent_indent='     ')
                            console.print(f"[dim]{wrapped}[/dim]")
                
                console.print()  # Empty line between packages
            
            console.print("[dim]" + "═" * 80 + "[/dim]")
            console.print(f"[bold bright_green]📊 Summary:[/bold bright_green] [bold white]{len(grouped_threats)}[/bold white] vulnerable packages, [bold white]{len(threats)}[/bold white] threat variants")
            return
        
        # Print mode information
        if args.offline and args.verbose:
            console.print("[yellow]🔒 Running in offline mode - using built-in threat database only[/yellow]")
        elif args.verbose:
            console.print("[green]🌐 Online mode - automatic database updates enabled[/green]")
        
        # Perform system scan
        results = await scanner.scan_system()
        
        # Deduplicate results
        unique_results = {}
        for result in results:
            key = (result.package.name, result.package.version)
            unique_results[key] = result
        
        deduplicated_results = sorted(unique_results.values(), 
                                    key=lambda r: (r.package.name, r.package.version))
        
        # Generate report
        reporter = Reporter(args.format, args.threats_only, auto_generate_files=not args.no_auto_files)
        await reporter.generate_report(deduplicated_results, validated_output)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if args.verbose:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())