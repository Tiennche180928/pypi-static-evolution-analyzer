#!/usr/bin/env python3
"""
PyPI Malware & Version Diff Analyzer (maloss-samples)
Author: Security Analysis Assistant
Description:
    Static analysis and version diffing tool for malicious PyPI packages.
    Safely inspects archives (.tar.gz, .tgz, .whl, .zip) and directories without
    executing any untrusted code (uses AST and static regex pattern matching).
"""

import argparse
import contextlib
import hashlib
import ast
import difflib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION_CHANGES_FILENAME = "version_changes.md"

# Ensure stdout handles UTF-8 on Windows
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ==========================================
# Color & Formatting Helpers
# ==========================================
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


def c(text: str, color: str, no_color: bool = False) -> str:
    if no_color or not sys.stdout.isatty():
        return text
    return f"{color}{text}{Colors.RESET}"


# ==========================================
# Static Heuristics & Malware Rules
# ==========================================
PATTERNS = {
    "COMMAND_EXECUTION": [
        (r"\b(os\.system|os\.popen|os\.spawn\w*)\b", "Execution via os command"),
        (r"\b(subprocess\.Popen|subprocess\.call|subprocess\.run|subprocess\.check_output)\b", "Subprocess execution"),
        (r"\b(pty\.spawn|os\.dup2)\b", "Interactive terminal / Reverse shell setup"),
    ],
    "DYNAMIC_EVAL": [
        (r"\b(exec|eval)\s*\(", "Dynamic code execution (exec/eval)"),
        (r"\bcompile\s*\(.+,\s*['\"]exec['\"]\)", "Dynamic code compilation"),
        (r"\b__import__\s*\(", "Dynamic module import"),
    ],
    "OBFUSCATION": [
        (r"\bbase64\.(b64decode|b64encode|b32decode|b16decode|standard_b64decode)\b", "Base64 payload encoding/decoding"),
        (r"\[::-1\]", "String reversal obfuscation"),
        (r"\bzlib\.decompress\b", "Zlib compressed payload decompression"),
        (r"\bcodecs\.decode\b", "Codecs decoded string/payload"),
        (r"(\\x[0-9a-fA-F]{2}){5,}", "Hex-encoded byte stream"),
    ],
    "NETWORK_EXFILTRATION": [
        (r"\b(socket\.socket|socket\.create_connection)\b", "Raw socket connection (C2 / Reverse shell)"),
        (r"\b(urllib\.request\.urlretrieve|urllib\.request\.urlopen|urllib2\.urlopen|requests\.(get|post|put)|http\.client)\b", "Outbound HTTP(S) download or request"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b", "Hardcoded IP address"),
        (r"https?://(?!example\.com|github\.com/|pypi\.org/)[a-zA-Z0-9_\-\.]+(?::\d+)?(?:/[^\s'\"<>]*)?", "Suspicious external URL/C2"),
    ],
    "RECONNAISSANCE_STEALER": [
        (r"\b(os\.environ|environ\.items|environ\.get)\b", "Environment variables harvesting (API tokens, secrets)"),
        (r"\b(getpass\.getuser|socket\.gethostname|platform\.uname|platform\.platform)\b", "System & user reconnaissance"),
        (r"(\.ssh|\.aws|\.bash_history|\.env|\.kube|Discord|wallets)", "Sensitive credential / token path access"),
        (r"(/etc/passwd|/etc/shadow)", "Unix system credentials access"),
    ],
    "INSTALL_HOOKS": [
        (r"\bcmdclass\s*=\s*\{.*['\"](install|develop|build_py|egg_info|bdist_wheel)['\"].*\}", "Custom setup.py cmdclass hook"),
        (r"\bclass\s+\w+\s*\(\s*(?:install|develop|build_py|egg_info)\s*\)\s*:", "Subclassing setup command class (runs code during pip install)"),
        (r"\batexit\.register\b", "Post-process exit hook (atexit)"),
    ],
}


class Finding:
    def __init__(self, category: str, description: str, file_path: str, line_no: int, snippet: str, severity: str = "HIGH"):
        self.category = category
        self.description = description
        self.file_path = file_path
        self.line_no = line_no
        self.snippet = snippet.strip()
        self.severity = severity

    def to_dict(self):
        return {
            "category": self.category,
            "description": self.description,
            "file": self.file_path,
            "line": self.line_no,
            "snippet": self.snippet,
            "severity": self.severity
        }


# ==========================================
# Safe Archive Extraction
# ==========================================
def extract_package_base_name(input_str: str) -> str:
    stem = Path(input_str).name
    for extension in [".tar.gz", ".tgz", ".whl", ".zip", ".py"]:
        if stem.lower().endswith(extension):
            stem = stem[:-len(extension)]
            break
    if str(input_str).lower().endswith(".whl"):
        return stem.split("-")[0].lower()
    match = re.match(r"^(.+?)-([vV]?\d.*)$", stem)
    return match.group(1).lower() if match else stem.lower()


def find_all_package_versions(pkg_name: str, search_roots: List[Path]) -> List[Tuple[str, Path]]:
    """Discover flat archives and package/version/src.zip datasets."""
    def normalized(name):
        return re.sub(r"[-_.]+", "-", name).lower()

    package_pattern = r"[-_.]+".join(re.escape(p) for p in re.split(r"[-_.]+", pkg_name))
    archive_pattern = re.compile(r"^" + package_pattern + r"-([vV]?\d.*?)\.(tar\.gz|tgz|whl|zip)$", re.I)
    directory_pattern = re.compile(r"^" + package_pattern + r"-([vV]?\d.*)$", re.I)
    version_pattern = re.compile(r"^[vV]?\d[0-9A-Za-z.!+_-]*$")
    candidates = defaultdict(list)
    seen = set()
    visited_packages = set()

    def archive_version(path):
        if path.suffix.lower() == ".whl":
            parts = path.name[:-4].split("-")
            if len(parts) >= 2 and normalized(parts[0]) == normalized(pkg_name):
                return parts[1]
            return None
        match = archive_pattern.match(path.name)
        return match.group(1) if match else None

    def priority(path):
        if path.is_dir():
            return 4
        name = path.name.lower()
        if name.endswith((".tar.gz", ".tgz")):
            return 0
        if name == "src.zip":
            return 3
        return 2 if name.endswith(".whl") else 1

    def add(version, path):
        real = path.resolve()
        if real in seen:
            return
        seen.add(real)
        candidates[version].append(path)

    def inspect_version(directory, version):
        # A release archive takes priority when a version folder also has src.zip.
        archives = [p for p in directory.iterdir() if p.is_file() and archive_version(p) == version]
        for path in archives:
            add(version, path)
        source_zip = directory / "src.zip"
        if source_zip.is_file():
            add(version, source_zip)
        if not archives and not source_zip.is_file():
            if any(p.is_file() and p.name != VERSION_CHANGES_FILENAME for p in directory.rglob("*")):
                add(version, directory)

    def inspect_package(directory):
        real = directory.resolve()
        if real in visited_packages:
            return
        visited_packages.add(real)
        for child in sorted(directory.iterdir()):
            if child.is_file():
                version = archive_version(child)
                if version:
                    add(version, child)
            elif child.is_dir() and not child.is_symlink():
                match = directory_pattern.match(child.name)
                version = match.group(1) if match else (child.name if version_pattern.fullmatch(child.name) else None)
                if version:
                    inspect_version(child, version)

    for root in search_roots:
        root = Path(root)
        if not root.is_dir():
            continue
        if normalized(root.name) == normalized(pkg_name):
            inspect_package(root)
        for item in sorted(root.iterdir()):
            if item.is_file():
                version = archive_version(item)
                if version:
                    add(version, item)
            elif item.is_dir() and not item.is_symlink():
                if normalized(item.name) == normalized(pkg_name):
                    inspect_package(item)
                else:
                    match = directory_pattern.match(item.name)
                    if match:
                        inspect_version(item, match.group(1))

    matched = []
    for version, paths in candidates.items():
        paths.sort(key=lambda p: (priority(p), str(p.resolve())))
        selected = paths[0]
        if len(paths) > 1:
            print("[!] {}=={}: {} candidate sources; selected {}".format(
                pkg_name, version, len(paths), selected), file=sys.stderr)
        matched.append((version, selected))

    def version_key(item):
        return tuple((0, int(part)) if part.isdigit() else (1, part.lower())
                     for part in re.split(r"(\d+)", str(item[0])))
    matched.sort(key=version_key)
    return matched


def count_python_sources(root_dir: Path) -> int:
    excluded = {".git", "venv", ".env", "__pycache__", "__MACOSX"}
    return sum(1 for p in list(root_dir.rglob("*.py")) + list(root_dir.rglob("*.pth"))
               if p.is_file() and not excluded.intersection(p.relative_to(root_dir).parts))


def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    try:
        base = base_dir.resolve()
        target = target_path.resolve()
        return target.is_relative_to(base)
    except Exception:
        return False


def extract_package(archive_or_dir: Path, dest_dir: Path) -> Path:
    """
    Safely extracts tar.gz, tgz, whl, zip, or copies directory to dest_dir.
    Strips the leading single root folder if one exists (e.g. ctx-0.2.6/ -> root)
    so packages can be compared uniformly.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    temp_extract = dest_dir / "_raw"
    temp_extract.mkdir(parents=True, exist_ok=True)

    if archive_or_dir.is_dir():
        for item in archive_or_dir.iterdir():
            if item.name == VERSION_CHANGES_FILENAME:
                continue
            target = temp_extract / item.name
            if item.is_dir():
                shutil.copytree(item, target, ignore=shutil.ignore_patterns(VERSION_CHANGES_FILENAME))
            else:
                shutil.copy2(item, target)

    elif archive_or_dir.suffix in [".tgz"] or archive_or_dir.name.endswith(".tar.gz"):
        with tarfile.open(archive_or_dir, "r:*") as tar:
            for member in tar.getmembers():
                dest = (temp_extract / member.name).resolve()
                if not is_safe_path(temp_extract, dest):
                    raise ValueError(f"Path traversal detected in archive: {member.name}")
            tar.extractall(path=temp_extract, filter="data" if hasattr(tarfile, "data_filter") else None)

    elif archive_or_dir.suffix in [".whl", ".zip"]:
        with zipfile.ZipFile(archive_or_dir, "r") as z:
            safe_members = []
            for member in z.infolist():
                name = member.filename
                if name.startswith("__MACOSX/") or name.startswith("__MACOSX\\") or "/__MACOSX/" in name:
                    continue
                if name.startswith("._") or "/._" in name or "\\._" in name:
                    continue
                dest = (temp_extract / name).resolve()
                if not is_safe_path(temp_extract, dest):
                    raise ValueError(f"Path traversal detected in zip: {name}")
                safe_members.append(member)
            z.extractall(temp_extract, members=safe_members)

    elif archive_or_dir.suffix == ".py":
        shutil.copy2(archive_or_dir, temp_extract / archive_or_dir.name)

    else:
        raise ValueError(f"Unsupported package format: {archive_or_dir}")

    # Normalize root: if there's only 1 top-level subdirectory, flatten it
    top_items = [p for p in temp_extract.iterdir() if p.name != "__MACOSX"]
    final_root = dest_dir / "unpacked"
    final_root.mkdir(parents=True, exist_ok=True)

    if len(top_items) == 1 and top_items[0].is_dir():
        for item in top_items[0].iterdir():
            shutil.move(str(item), str(final_root / item.name))
    else:
        for item in top_items:
            shutil.move(str(item), str(final_root / item.name))

    shutil.rmtree(temp_extract, ignore_errors=True)
    return final_root


# ==========================================
# PyPI Online Registry Fetcher
# ==========================================
def fetch_pypi_package(package_name: str, version: Optional[str], dest_dir: Path) -> Path:
    """
    Downloads package tarball/wheel from PyPI official JSON API.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "PyPI-Malware-Analyzer/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())

    releases = data.get("releases", {})
    if not releases:
        raise ValueError(f"No releases found for package '{package_name}' on PyPI.")

    if not version:
        version = data.get("info", {}).get("version")
        if not version or version not in releases:
            version = list(releases.keys())[-1]

    if version not in releases or not releases[version]:
        available = ", ".join(list(releases.keys())[-10:])
        raise ValueError(f"Version '{version}' not found for '{package_name}'. Available: {available}")

    files = releases[version]
    # Prefer source dist (.tar.gz), then wheel
    chosen_file = None
    for f in files:
        if f["packagetype"] == "sdist":
            chosen_file = f
            break
    if not chosen_file and files:
        chosen_file = files[0]

    download_url = chosen_file["url"]
    filename = chosen_file["filename"]
    save_path = dest_dir / filename

    print(f"[*] Downloading {package_name}=={version} ({filename}) from PyPI...")
    urllib.request.urlretrieve(download_url, save_path)
    return save_path


# ==========================================
# AST & Static Code Scanner
# ==========================================
def scan_python_code(file_path: Path, rel_path: str) -> List[Finding]:
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return findings

    lines = content.splitlines()

    # 1. Regex pattern scan
    for category, pattern_list in PATTERNS.items():
        for pat, desc in pattern_list:
            regex = re.compile(pat, re.IGNORECASE)
            for idx, line in enumerate(lines, 1):
                # Ignore innocuous comments and plain docs
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if regex.search(line):
                    severity = "CRITICAL" if category in ["INSTALL_HOOKS", "DYNAMIC_EVAL", "COMMAND_EXECUTION"] else "HIGH"
                    findings.append(Finding(category, desc, rel_path, idx, line, severity))

    # 2. Check Python .pth persistence files
    if file_path.suffix == ".pth":
        for idx, line in enumerate(lines, 1):
            if line.strip().startswith("import "):
                findings.append(Finding(
                    "INSTALL_HOOKS",
                    "Python startup persistence/execution hook via .pth file",
                    rel_path,
                    idx,
                    line,
                    "CRITICAL"
                ))

    # 3. AST structural inspection (check top-level setup.py execution)
    if file_path.name == "setup.py":
        try:
            tree = ast.parse(content, filename=str(file_path))
            for node in tree.body:
                # Detect top-level statements that are NOT imports, class/func defs, or setup()
                if isinstance(node, (ast.Expr, ast.Assign, ast.Try, ast.With, ast.If)):
                    # Check if it calls setup(...)
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                        func_name = getattr(node.value.func, "id", None)
                        if func_name == "setup":
                            continue
                    snippet = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                    if not snippet.strip().startswith("#"):
                        # If node references socket, os, urllib, requests
                        node_str = ast.dump(node)
                        if any(k in node_str for k in ["socket", "urlopen", "requests", "environ", "system", "Popen", "connect"]):
                            findings.append(Finding(
                                "IMMEDIATE_EXECUTION",
                                "Top-level code in setup.py executes immediately on pip install",
                                rel_path,
                                node.lineno,
                                snippet,
                                "CRITICAL"
                            ))
        except SyntaxError:
            pass

    return findings


def scan_package_dir(root_dir: Path) -> List[Finding]:
    all_findings = []
    targets = list(root_dir.rglob("*.py")) + list(root_dir.rglob("*.pth"))
    for p in targets:
        if any(part in p.parts for part in [".git", "venv", ".env", "__pycache__", "__MACOSX"]):
            continue
        rel = str(p.relative_to(root_dir))
        all_findings.extend(scan_python_code(p, rel))
    return all_findings


# ==========================================
# Diffing & Evolution Analysis
# ==========================================
def history_file_map(root: Path) -> Dict[str, Path]:
    """Ignore only the generated report, so a rerun never diffs its own output."""
    result = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.name == VERSION_CHANGES_FILENAME:
            continue
        if not is_safe_path(root, path):
            raise ValueError("Source file points outside the extracted package: " + str(path))
        result[path.relative_to(root).as_posix()] = path
    return result


def python_change_description(old_text: str, new_text: str) -> str:
    def units(text):
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return {}
        result = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                label = ("lớp " if isinstance(node, ast.ClassDef) else "hàm ") + node.name
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = sorted({item.id for target in targets for item in ast.walk(target) if isinstance(item, ast.Name)})
                if not names:
                    continue
                label = "biến " + ", ".join(names)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                label = "import " + (getattr(node, "module", None) or "") + " " + ", ".join(n.name for n in node.names)
            else:
                continue
            result[label] = ast.dump(node, include_attributes=False)
        return result
    before, after = units(old_text), units(new_text)
    pieces = []
    for names, label in (
        (set(after) - set(before), "Thêm"),
        (set(before) - set(after), "Bỏ"),
        ({name for name in before.keys() & after.keys() if before[name] != after[name]}, "Sửa"),
    ):
        if names:
            pieces.append(label + " " + ", ".join(sorted(names)))
    return "; ".join(pieces)


def file_history_change(relative: str, before: Optional[Path], after: Optional[Path]) -> Optional[Dict]:
    old_bytes = before.read_bytes() if before else None
    new_bytes = after.read_bytes() if after else None
    if old_bytes == new_bytes:
        return None
    kind = "added" if before is None else ("removed" if after is None else "modified")
    old_label = "a/" + relative if before else "/dev/null"
    new_label = "b/" + relative if after else "/dev/null"
    old_sha = hashlib.sha256(old_bytes).hexdigest() if old_bytes is not None else None
    new_sha = hashlib.sha256(new_bytes).hexdigest() if new_bytes is not None else None
    binary = False
    try:
        if b"\x00" in (old_bytes or b"") or b"\x00" in (new_bytes or b""):
            raise UnicodeError("NUL byte")
        old_text = (old_bytes or b"").decode("utf-8")
        new_text = (new_bytes or b"").decode("utf-8")
    except UnicodeError:
        binary = True
        old_text = new_text = ""
    additions = deletions = 0
    if binary:
        patch = (
            "Tệp nhị phân hoặc không giải mã được UTF-8; không có diff văn bản.\n"
            "SHA-256 trước: " + (old_sha or "(không tồn tại)") + "\n"
            "SHA-256 sau:   " + (new_sha or "(không tồn tại)") + "\n"
        )
        description = {"added": "Thêm tệp", "removed": "Xóa tệp", "modified": "Đổi nội dung tệp"}[kind] + " nhị phân/không phải UTF-8."
    else:
        def quote_name(name):
            return json.dumps(name, ensure_ascii=False) if any(c in name for c in '\t\n\r"\\') else name
        chunks = []
        in_hunk = False
        for line in difflib.unified_diff(
            old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
            fromfile=quote_name(old_label), tofile=quote_name(new_label), lineterm="\n"
        ):
            if line.startswith("@@"):
                in_hunk = True
            elif in_hunk:
                additions += line.startswith("+")
                deletions += line.startswith("-")
            chunks.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
        patch = "".join(chunks)
        if not patch:
            # Creating/removing an empty file has no text hunk, but is still a change.
            mode = "new file mode 100644\n" if kind == "added" else "deleted file mode 100644\n"
            patch = "diff --git {} {}\n{}".format(
                quote_name("a/" + relative), quote_name("b/" + relative), mode)
        description = {"added": "Thêm tệp", "removed": "Xóa tệp", "modified": "Sửa nội dung tệp"}[kind]
        if relative.lower().endswith(".py"):
            structure = python_change_description(old_text, new_text)
            if structure:
                description += ". " + structure
        description += ". +{} dòng, -{} dòng.".format(additions, deletions)
    return {
        "path": relative, "kind": kind, "binary": binary,
        "before_sha256": old_sha, "after_sha256": new_sha,
        "additions": additions, "deletions": deletions,
        "description": description, "patch_text": patch,
        "diff": patch.splitlines()
    }


def compare_packages(dir_a: Path, label_a: str, dir_b: Path, label_b: str) -> Dict:
    files_a, files_b = history_file_map(dir_a), history_file_map(dir_b)
    changes = []
    for relative in sorted(files_a.keys() | files_b.keys()):
        change = file_history_change(relative, files_a.get(relative), files_b.get(relative))
        if change:
            changes.append(change)
    return {
        "label_a": label_a, "label_b": label_b,
        "added_files": [f["path"] for f in changes if f["kind"] == "added"],
        "removed_files": [f["path"] for f in changes if f["kind"] == "removed"],
        "modified_files": [f for f in changes if f["kind"] == "modified"],
        "file_changes": changes
    }



# ==========================================
# Sample Locator & Discovery
# ==========================================
def find_sample(query: str, search_roots: List[Path]) -> Optional[Path]:
    # 1. Exact path
    direct_p = Path(query)
    if direct_p.exists():
        return direct_p

    # 2. Search inside search_roots
    for root in search_roots:
        if not root.exists():
            continue
        # Direct child
        candidate = root / query
        if candidate.exists():
            return candidate

        # Check with extensions
        for ext in [".tar.gz", ".tgz", ".whl", ".zip"]:
            cand = root / f"{query}{ext}"
            if cand.exists():
                return cand

        # Glob match
        matches = list(root.glob(f"*{query}*"))
        if matches:
            # Prefer exact starts
            matches.sort(key=lambda x: (0 if x.name.startswith(query) else 1, len(x.name)))
            return matches[0]

    return None


def list_pypi_samples(pypi_dir: Path):
    if not pypi_dir.exists():
        print(f"Error: Directory {pypi_dir} not found.")
        return

    archive_exts = [".tar.gz", ".tgz", ".whl", ".zip"]

    def parse_name(fname: str):
        clean = fname
        for ext in archive_exts:
            if clean.endswith(ext):
                clean = clean[:-len(ext)]
                break
        m = re.match(r"^([a-zA-Z0-9_\-\.]+?)-([\dvV].*)$", clean)
        if m:
            return m.group(1).lower(), m.group(2)
        return clean.lower(), "standalone"

    catalog = defaultdict(list)
    format_counts = Counter()

    # 1. Root files
    for item in pypi_dir.iterdir():
        if item.is_file():
            ext = next((e for e in archive_exts if item.name.endswith(e)), None)
            if ext:
                pkg, ver = parse_name(item.name)
                catalog[pkg].append((ver, item))
                format_counts[ext] += 1
            elif item.suffix == ".py":
                catalog[item.stem.lower()].append(("1.0", item))
                format_counts[".py"] += 1

    # 2. Subdirectories
    subdirs = [d for d in pypi_dir.iterdir() if d.is_dir() and d.name != ".git"]
    for d in subdirs:
        if d.name == "request-investigation":
            for f in d.iterdir():
                if f.is_file():
                    ext = next((e for e in archive_exts if f.name.endswith(e)), None)
                    if ext:
                        pkg, ver = parse_name(f.name)
                        catalog[pkg].append((ver, f))
                        format_counts[ext] += 1
        else:
            for item in d.iterdir():
                if item.is_file():
                    ext = next((e for e in archive_exts if item.name.endswith(e)), None)
                    if ext:
                        pkg, ver = parse_name(item.name)
                        catalog[pkg].append((ver, item))
                        format_counts[ext] += 1
                    elif item.suffix == ".py":
                        catalog[d.name.lower()].append(("standalone", item))
                        format_counts[".py"] += 1
                elif item.is_dir():
                    m = re.match(rf"^{re.escape(d.name)}-([\dvV].*)$", item.name, re.IGNORECASE)
                    ver = m.group(1) if m else item.name
                    catalog[d.name.lower()].append((ver, item))
                    format_counts["dir"] += 1

    total_pkgs = len(catalog)
    total_versions = sum(len(v) for v in catalog.values())
    multi_v = {k: v for k, v in catalog.items() if len(set(x[0] for x in v)) > 1}
    single_v = {k: v for k, v in catalog.items() if len(set(x[0] for x in v)) == 1}

    print(f"\n{Colors.BOLD}=== PyPI Samples Overview & Census ==={Colors.RESET}")
    print(f"Path: {pypi_dir.resolve()}\n")
    print(f"  * {Colors.BOLD}Total Unique Packages:{Colors.RESET}       {c(str(total_pkgs), Colors.CYAN)}")
    print(f"  * {Colors.BOLD}Total Version Samples:{Colors.RESET}       {c(str(total_versions), Colors.GREEN)}")
    print(f"  * {Colors.BOLD}Multi-Version Packages:{Colors.RESET}      {c(str(len(multi_v)), Colors.YELLOW)} (Ideal for evolution diffing)")
    print(f"  * {Colors.BOLD}Single-Version Packages:{Colors.RESET}     {str(len(single_v))}")

    print(f"\n{Colors.BOLD}Format Distribution:{Colors.RESET}")
    for fmt, cnt in format_counts.most_common():
        print(f"  - {fmt:<10}: {cnt:4} samples")

    print(f"\n{Colors.BOLD}{Colors.CYAN}--- All Multi-Version Packages ({len(multi_v)} packages) ---{Colors.RESET}")
    for pkg, v_list in sorted(multi_v.items(), key=lambda x: len(x[1]), reverse=True):
        uniq_v = sorted(list(set(x[0] for x in v_list)))
        v_str = ", ".join(uniq_v[:6]) + ("..." if len(uniq_v) > 6 else "")
        print(f"  * {c(pkg, Colors.YELLOW, False):<20}: {len(uniq_v):2} versions [{v_str}]")

    print(f"\n{Colors.BOLD}{Colors.BLUE}--- Subdirectories in pypi-samples ({len(subdirs)}) ---{Colors.RESET}")
    for d in sorted(subdirs)[:10]:
        print(f"  [DIR] {d.name}/")
    if len(subdirs) > 10:
        print(f"  ... and {len(subdirs) - 10} more subdirectories.")


# ==========================================
# CLI Execution & Reporting
# ==========================================
def print_scan_report(findings: List[Finding], sample_name: str, no_color: bool = False, scanned_files: Optional[int] = None):
    print(f"\n{c('='*70, Colors.BOLD, no_color)}")
    print(f"{c('MALWARE SECURITY ANALYSIS REPORT:', Colors.BOLD, no_color)} {sample_name}")
    print(f"{c('='*70, Colors.BOLD, no_color)}")

    if scanned_files is not None:
        print("Python/.pth files inspected: {}".format(scanned_files))
    if scanned_files == 0:
        print(c("\n[!] No Python/.pth source was inspected. Analysis is incomplete.", Colors.YELLOW, no_color))
        return

    if not findings:
        print(c("\n[+] No rules matched; this does not establish that the sample is benign.", Colors.GREEN, no_color))
        return

    # Threat level
    has_critical = any(f.severity == "CRITICAL" for f in findings)
    threat = "CRITICAL / MALICIOUS" if has_critical else "SUSPICIOUS / HIGH RISK"
    color = Colors.RED if has_critical else Colors.YELLOW
    print(f"\nThreat Assessment: {c(threat, color, no_color)} ({len(findings)} findings)")

    # Group by category
    by_cat = defaultdict(list)
    for f in findings:
        by_cat[f.category].append(f)

    for cat, items in by_cat.items():
        print(f"\n{c('► ' + cat, Colors.BOLD + Colors.CYAN, no_color)} ({len(items)} hits):")
        for item in items:
            sev_badge = c(f"[{item.severity}]", Colors.RED if item.severity == "CRITICAL" else Colors.YELLOW, no_color)
            print(f"  {sev_badge} {item.file_path}:{item.line_no} - {item.description}")
            print(f"     {c('Code:', Colors.MAGENTA, no_color)} {item.snippet}")


def markdown_text(value) -> str:
    value = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return re.sub(r"([\\`*_\[\]<>|])", r"\\\1", value)


def markdown_code(value) -> str:
    value = str(value).replace("\r", "\\r").replace("\n", "\\n").replace("|", "\\|")
    longest = max((len(m.group()) for m in re.finditer(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if value.startswith("`") or value.endswith("`") else ""
    return fence + padding + value + padding + fence


def code_block(content: str, language: str = "diff") -> str:
    longest = max((len(m.group()) for m in re.finditer(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return fence + language + "\n" + content + ("" if content.endswith("\n") else "\n") + fence + "\n"


def render_version_history(package: str, info: Dict, previous: Optional[Dict], diff: Optional[Dict]) -> str:
    md = ["# {} — {}".format(markdown_code(package), markdown_code(info["version"])), ""]
    md += ["- **Version hiện tại:** " + markdown_code(info["version"]),
           "- **Version đối chiếu:** " + (markdown_code(previous["version"]) if previous else "Chưa có trong dữ liệu"),
           "- **Nguồn hiện tại:** " + markdown_code(info["path"])]
    if previous:
        md.append("- **Nguồn đối chiếu:** " + markdown_code(previous["path"]))
    md += ["", "## 1. Mô tả thay đổi", ""]
    if previous is None:
        md += ["Đây là bản đầu tiên có trong dữ liệu được chọn. Chưa có bản trước để xác định thay đổi.",
               "Không suy ra đây là lần phát hành đầu tiên hoặc phiên bản lành tính.", "",
               "Số tệp trong nguồn đã đọc: **{}**.".format(info["file_count"])]
    else:
        changes = diff["file_changes"]
        md += ["So sánh **{} → {}**.".format(markdown_text(previous["version"]), markdown_text(info["version"])), "",
               "Thêm **{}** tệp · Sửa **{}** tệp · Xóa **{}** tệp.".format(
                   len(diff["added_files"]), len(diff["modified_files"]), len(diff["removed_files"])), ""]
        if changes:
            md += ["| Tệp | Thay đổi | Mô tả |", "|---|---|---|"]
            for item in changes:
                md.append("| {} | {} | {} |".format(markdown_code(item["path"]),
                          {"added": "Thêm", "modified": "Sửa", "removed": "Xóa"}[item["kind"]],
                          markdown_text(item["description"])))
        else:
            md.append("Không phát hiện thay đổi về đường dẫn hoặc nội dung tệp giữa hai nguồn đã đọc.")
        md += ["", "Mô tả được tạo từ thay đổi của tệp và cấu trúc Python đọc được; không suy diễn mục đích của tác giả."]
    md += ["", "## 2. Diff đối chiếu", ""]
    if previous is None:
        md.append("Chưa có version trước để tạo diff.")
    elif not diff["file_changes"]:
        md.append("Không có diff nội dung.")
    else:
        for item in diff["file_changes"]:
            md += ["### " + markdown_code(item["path"]), "",
                   code_block(item["patch_text"], "text" if item["binary"] else "diff")]
    return "\n".join(md).rstrip() + "\n"


def infer_history_identity(path: Path) -> Tuple[str, str]:
    path = path.resolve()
    directory = path if path.is_dir() else path.parent
    stem = path.name
    for extension in (".tar.gz", ".tgz", ".whl", ".zip", ".py"):
        if stem.lower().endswith(extension):
            stem = stem[:-len(extension)]
            break
    if path.suffix.lower() == ".whl":
        parts = stem.split("-")
        if len(parts) >= 2:
            return parts[0], parts[1]
    match = re.fullmatch(r"(.+?)-([vV]?\d.*)", stem)
    if match:
        return match.group(1), match.group(2)
    if re.fullmatch(r"[vV]?\d[0-9A-Za-z.!+_-]*", directory.name):
        return directory.parent.name, directory.name
    match = re.fullmatch(r"(.+?)-([vV]?\d.*)", directory.name)
    if match:
        return match.group(1), match.group(2)
    return extract_package_base_name(str(path)), "unknown"


def history_component(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z._+-]+", "_", value).strip(".") or "unknown"


def version_history_path(package: str, version: str, source: Path,
                         cwd: Path, temporary_root: Path) -> Path:
    source = source.resolve()
    normalize = lambda s: re.sub(r"[-_.]+", "-", s).lower()
    parent_match = re.fullmatch(r"(.+?)-([vV]?\d.*)", source.parent.name)
    # A registry reference is temporary; its report must survive cleanup.
    if is_safe_path(temporary_root, source):
        directory = cwd / history_component(package) / history_component(version)
    elif source.is_dir():
        directory = source
    elif source.parent.name == version or (parent_match and
          normalize(parent_match.group(1)) == normalize(package) and parent_match.group(2) == version):
        directory = source.parent
    else:
        parent = source.parent
        package_root = parent if normalize(parent.name) == normalize(package) else parent / history_component(package)
        directory = package_root / history_component(version)
    return directory / VERSION_CHANGES_FILENAME


def write_history_file(path: Path, content: str):
    if path.is_symlink():
        raise ValueError("Refusing to overwrite a report symlink: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=path.parent,
                                         prefix=".version_changes_", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        os.replace(str(temporary), str(path))
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def resolve_history_source(query: str, search_dirs: List[Path]) -> Tuple[str, str, Path]:
    source = find_sample(query, search_dirs)
    if source is None:
        raise ValueError("Local sample not found: " + query)
    source = source.resolve()
    if source.is_dir() and (source / "src.zip").is_file():
        source = source / "src.zip"
    elif source.is_dir():
        versions = find_all_package_versions(source.name, [source, source.parent])
        if versions:
            version, selected = versions[-1]
            return source.name, version, selected.resolve()
    package, version = infer_history_identity(source)
    return package, version, source


def execute_diff_history(args, parser, search_dirs: List[Path], cwd: Path, temp_workspace: Path):
    selected_pair = bool(args.sample_b or args.pypi_clean or args.v1 or args.v2 or args.first_last)
    if args.pypi_clean:
        package, local_version, local_source = resolve_history_source(args.sample_a, search_dirs)
        download_dir = temp_workspace / "registry"
        download_dir.mkdir()
        with contextlib.redirect_stdout(sys.stderr):
            reference = fetch_pypi_package(args.pypi_clean, args.pypi_version, download_dir)
        _, reference_version = infer_history_identity(reference)
        # Registry source is the reference; write the transition into the local target.
        versions = [(reference_version, reference), (local_version, local_source)]
    elif args.sample_b:
        package, version_a, source_a = resolve_history_source(args.sample_a, search_dirs)
        _, version_b, source_b = resolve_history_source(args.sample_b, search_dirs)
        versions = [(version_a, source_a), (version_b, source_b)]
    else:
        package = extract_package_base_name(args.sample_a)
        direct = Path(args.sample_a)
        roots = list(search_dirs)
        if direct.exists():
            direct = direct.resolve()
            if direct.is_file() or re.fullmatch(r"[vV]?\d[0-9A-Za-z.!+_-]*", direct.name):
                package, _ = infer_history_identity(direct)
            roots = [direct if direct.is_dir() else direct.parent, direct.parent, direct.parent.parent] + roots
        versions = find_all_package_versions(package, roots)
        if not versions:
            package, version, source = resolve_history_source(args.sample_a, search_dirs)
            versions = [(version, source)]
        if selected_pair:
            mapping = dict(versions)
            if args.v1 and args.v1 not in mapping:
                parser.error("Base version not found: " + args.v1)
            if args.v2 and args.v2 not in mapping:
                parser.error("Target version not found: " + args.v2)
            if len(versions) < 2:
                parser.error("At least two available versions are required for a selected pair.")
            version_a = args.v1 or versions[0][0]
            version_b = args.v2 or versions[-1][0]
            if version_a == version_b:
                parser.error("Base and target versions must differ.")
            versions = [(version_a, mapping[version_a]), (version_b, mapping[version_b])]

    infos = []
    for index, (version, source) in enumerate(versions):
        source = source.resolve()
        unpacked = extract_package(source, temp_workspace / ("history_{:04d}".format(index)))
        infos.append({"version": version, "path": source, "dir": unpacked,
                      "file_count": len(history_file_map(unpacked))})

    records = []
    for index in range(1 if selected_pair else 0, len(infos)):
        info = infos[index]
        previous = infos[index - 1] if index else None
        diff = compare_packages(previous["dir"], previous["version"], info["dir"], info["version"]) if previous else None
        output = version_history_path(package, info["version"], info["path"], cwd, temp_workspace)
        records.append({"version": info["version"], "previous_version": previous["version"] if previous else None,
                        "source": str(info["path"]), "output": str(output), "diff": diff,
                        "markdown": render_version_history(package, info, previous, diff)})

    combined = "\n---\n\n".join(record["markdown"] for record in records)
    writes = [(Path(record["output"]), record["markdown"]) for record in records]
    if args.out_dir:
        writes += [(Path(args.out_dir) / history_component(package) / history_component(record["version"]) /
                    VERSION_CHANGES_FILENAME, record["markdown"]) for record in records]
    if args.report:
        writes.append((Path(args.report), combined))

    # Validate destinations before saving any reports.
    pending = {}
    source_files = {info["path"].resolve() for info in infos if info["path"].is_file()}
    for path, content in writes:
        resolved = path.resolve()
        if path.is_symlink() or resolved in source_files:
            raise ValueError("Report destination conflicts with a source or symlink: " + str(path))
        if resolved in pending and pending[resolved] != content:
            raise ValueError("Report outputs overlap; choose a different --report or --out-dir: " + str(path))
        pending[resolved] = content
    for path, content in pending.items():
        write_history_file(path, content)
        print("[+] Saved: " + str(path), file=sys.stderr)
    if args.json:
        print(json.dumps({"pkg_name": package, "versions": [i["version"] for i in infos], "reports": records},
                         indent=2, ensure_ascii=False))
    else:
        print(combined, end="")



def export_scan_report(output_file: Path, findings: List[Finding], sample_name: str, scanned_files: int):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    md = ["# PyPI Static Scan: " + markdown_code(sample_name), "",
          "- **Python/.pth files inspected:** {}".format(scanned_files), ""]
    if scanned_files == 0:
        md.append("**Coverage: INCOMPLETE.** No supported source files were inspected.")
    elif not findings:
        md.append("No rules matched. This does not establish that the sample is benign.")
    else:
        md += ["| Severity | File:Line | Category | Description | Code Snippet |",
               "|---|---|---|---|---|"]
        for finding in findings:
            md.append("| {} | {} | {} | {} | {} |".format(
                markdown_text(finding.severity), markdown_code(finding.file_path + ":" + str(finding.line_no)),
                markdown_code(finding.category), markdown_text(finding.description), markdown_code(finding.snippet)))
    output_file.write_text("\n".join(md) + "\n", encoding="utf-8")
    print("[+] Report exported to: " + str(output_file.resolve()))


def main():
    parser = argparse.ArgumentParser(
        description="PyPI Malware Static Analysis & Version Diffing Tool (maloss-samples)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  1. List all samples and multi-version packages:
     python pypi_analyzer.py list

  2. Scan a single sample for malware/triggers:
     python pypi_analyzer.py scan 10Cent10
     python pypi_analyzer.py scan pypi-samples/ctx-0.2.6.tar.gz

  3. Diff two local versions:
     python pypi_analyzer.py diff pypi-samples/ctx-0.1.2-1.tar.gz pypi-samples/ctx-0.2.6.tar.gz
     python pypi_analyzer.py diff aws-login0tool-0.0.1.tar.gz aws-login0tool-0.0.14.tar.gz

  4. Compare a local sample against a PyPI reference:
     python pypi_analyzer.py diff pypi-samples/ctx-0.2.6.tar.gz --pypi-clean ctx --pypi-version 0.1.2

  5. Save an additional combined report (per-version reports are always saved):
     python pypi_analyzer.py diff pypi-samples/ctx-0.1.2-1.tar.gz pypi-samples/ctx-0.2.6.tar.gz --report ctx_report.md
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: list
    list_parser = subparsers.add_parser("list", help="List available PyPI samples in repo or directory")
    list_parser.add_argument("target_dir", nargs="?", default=None, help="Directory to inspect (default: auto-detected)")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a sample for malicious patterns")
    scan_parser.add_argument("sample", help="Package name or file path")
    scan_parser.add_argument("--report", help="Path to export Markdown report")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    # Command: diff
    diff_parser = subparsers.add_parser("diff", help="Compare versions of a package (auto-analyzes entire evolution chain if >2 versions)")
    diff_parser.add_argument("sample_a", help="Package name (e.g. 'litellm', 'ctx', 'aws-login0tool') or sample path")
    diff_parser.add_argument("sample_b", nargs="?", default=None, help="Second sample (optional: auto-detected if omitted)")
    diff_parser.add_argument("--v1", help="Specific base version to select (e.g. 0.1.2-1)")
    diff_parser.add_argument("--v2", help="Specific target version to select (e.g. 0.2.6)")
    diff_parser.add_argument("--first-last", action="store_true", help="Compare only the earliest and latest version instead of full chain")
    diff_parser.add_argument("--all-diffs", action="store_true", help="Compatibility option; all diffs are now always shown")
    diff_parser.add_argument("--pypi-clean", help="Fetch this package from PyPI as a comparison reference")
    diff_parser.add_argument("--pypi-version", help="Specific version to fetch from PyPI")
    diff_parser.add_argument("--report", help="Optional additional combined Markdown report")
    diff_parser.add_argument("--out-dir", help="Optional additional copies under DIR/package/version/version_changes.md")
    diff_parser.add_argument("--json", action="store_true", help="Output as JSON")
    diff_parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    repo_root = Path(__file__).parent.resolve()
    cwd = Path.cwd().resolve()

    def resolve_sample_dir(custom_path=None) -> Path:
        if custom_path:
            p = Path(custom_path).resolve()
            if p.exists() and p.is_dir():
                return p
            print(f"Warning: Specified directory '{custom_path}' not found. Falling back to auto-detection.")

        candidates = [
            cwd / "pypi-samples",
            repo_root / "pypi-samples",
            cwd,
            repo_root,
        ]
        # Prefer directory that actually contains Python archive samples
        for cand in candidates:
            if cand.exists() and cand.is_dir():
                has_samples = any(
                    next(cand.glob(f"*{ext}"), None) is not None
                    for ext in [".tar.gz", ".tgz", ".whl", ".zip"]
                )
                if has_samples:
                    return cand

        # Fallback to first existing directory
        for cand in candidates:
            if cand.exists() and cand.is_dir() and cand.name != ".git":
                return cand
        return cwd

    active_dir = resolve_sample_dir(getattr(args, "target_dir", None))
    search_dirs = [
        active_dir,
        active_dir / "request-investigation",
        cwd / "pypi-samples",
        repo_root / "pypi-samples",
        cwd,
        repo_root,
    ]

    if args.command == "list":
        list_pypi_samples(active_dir)
        return

    if not args.command:
        parser.print_help()
        return

    temp_workspace = Path(tempfile.mkdtemp(prefix="pypi_analysis_"))
    try:
        if args.command == "scan":
            sample_path = find_sample(args.sample, search_dirs)
            base_pkg = extract_package_base_name(args.sample)
            if sample_path and sample_path.is_dir():
                # A dataset package folder contains archives, not directly scannable source.
                dataset_versions = find_all_package_versions(base_pkg, search_dirs)
                if dataset_versions:
                    sample_path = dataset_versions[-1][1]
                    print("[*] Selected latest local version: {} ({})".format(dataset_versions[-1][0], sample_path))
                elif (sample_path / "src.zip").is_file():
                    sample_path = sample_path / "src.zip"
            if not sample_path:
                base_pkg = extract_package_base_name(args.sample)
                all_v = find_all_package_versions(base_pkg, search_dirs)
                if all_v:
                    sample_path = all_v[-1][1]
                    print(f"[*] Package '{base_pkg}' has {len(all_v)} versions. Scanning latest: v{all_v[-1][0]} ({sample_path.name})")
                else:
                    print(f"Error: Sample '{args.sample}' not found in pypi-samples.")
                    sys.exit(1)

            print(f"[*] Extracting and analyzing: {sample_path.name}")
            unpacked = extract_package(sample_path, temp_workspace / "target")
            findings = scan_package_dir(unpacked)

            if args.json:
                print(json.dumps([f.to_dict() for f in findings], indent=2))
            else:
                print_scan_report(findings, sample_path.name, args.no_color, count_python_sources(unpacked))

            if args.report:
                export_scan_report(Path(args.report), findings, str(sample_path), count_python_sources(unpacked))

        elif args.command == "diff":
            try:
                execute_diff_history(args, parser, search_dirs, cwd, temp_workspace)
            except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
                print("Error: " + str(error), file=sys.stderr)
                raise SystemExit(1)

    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)


if __name__ == "__main__":
    main()
