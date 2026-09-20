"""Optional dependency vulnerability checks using the public OSV API."""

from __future__ import annotations

import json
import re
from typing import Any

import requests

OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|@)\s*([A-Za-z0-9_.+!-]+)", line)
        if match:
            out.append(match.groups())
    return out


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            if isinstance(version, str):
                clean = version.lstrip("^~>=< ")
                if re.match(r"^\d", clean):
                    out.append((name, clean))
    return out


def _parse_go_mod(text: str) -> list[tuple[str, str]]:
    return [(a, b) for a, b in re.findall(r"^\s*([^\s]+)\s+(v\d[^\s]+)", text, re.M)]


def _parse_cargo(text: str) -> list[tuple[str, str]]:
    return [(a, b) for a, b in re.findall(r"^\s*([A-Za-z0-9_-]+)\s*=\s*["']?([0-9][^"'\n ]*)", text, re.M)]


def extract_dependencies(path: str, text: str) -> list[tuple[str, str]]:
    try:
        if path.lower().endswith("requirements.txt"):
            return _parse_requirements(text)
        if path.lower().endswith("package.json"):
            return _parse_package_json(text)
        if path.lower().endswith("go.mod"):
            return _parse_go_mod(text)
        if path.lower().endswith("cargo.toml"):
            return _parse_cargo(text)
    except (ValueError, json.JSONDecodeError):
        return []
    return []


def scan_dependencies(dependencies: list[tuple[str, str]], timeout: int = 15) -> list[dict[str, Any]]:
    if not dependencies:
        return []
    payload = {"queries": [{"package": {"name": name}, "version": version} for name, version in dependencies]}
    response = requests.post(OSV_BATCH, json=payload, timeout=timeout)
    response.raise_for_status()
    results = response.json().get("results", [])
    findings = []
    for (name, version), result in zip(dependencies, results):
        for vuln in result.get("vulns", []):
            findings.append({
                "id": vuln.get("id", "OSV"),
                "package": name,
                "version": version,
                "severity": "high",
                "summary": vuln.get("summary") or vuln.get("details", "Known vulnerability"),
                "url": (vuln.get("references") or [{}])[0].get("url"),
            })
    return findings
