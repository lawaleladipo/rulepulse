"""Static Detection-as-Code (.yaral) hygiene auditor with live dead-log cross-referencing."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Set

RULE_HEADER_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_]+)\s*\{", re.MULTILINE)
EVENTS_BLOCK_RE = re.compile(r"\bevents\s*:\s*(.*?)\b(?:match|outcome|condition)\s*:", re.DOTALL)
LOG_TYPE_RE = re.compile(r'metadata\.log_type\s*=\s*"([A-Z0-9_]+)"')
MITRE_META_RE = re.compile(r"\b(?:mitre_attack|tactic|technique|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
RESERVED_COUNT_RE = re.compile(r"\$count\s*=")
PERL_NOCASE_FLAG_RE = re.compile(r"/[^/\n]+/i\b")


@dataclass
class StaticRuleAuditFinding:
    file_path: str
    rule_name: str
    referenced_log_types: List[str]
    dead_log_types: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)


def _normalize_events_fingerprint(text: str) -> str:
    match = EVENTS_BLOCK_RE.search(text)
    if not match:
        return ""
    body = re.sub(r"//.*", "", match.group(1))
    body = re.sub(r"\s+", " ", body).strip().lower()
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16] if body else ""


def audit_yaral_directory(
    rules_dir: Path,
    *,
    dead_log_sources: Iterable[str] = (),
) -> List[StaticRuleAuditFinding]:
    """Audit .yaral files for duplicates, missing ATT&CK tags, syntax traps, and dead log sources."""
    dead_set: Set[str] = {s.strip().upper() for s in dead_log_sources}
    seen_names: Dict[str, str] = {}
    seen_fingerprints: Dict[str, str] = {}
    findings: List[StaticRuleAuditFinding] = []

    for yaral_file in sorted(rules_dir.glob("*.yaral")):
        raw = yaral_file.read_text(encoding="utf-8")
        header = RULE_HEADER_RE.search(raw)
        rule_name = header.group(1) if header else yaral_file.stem
        log_types = sorted(set(LOG_TYPE_RE.findall(raw)))
        dead_refs = [lt for lt in log_types if lt in dead_set]
        issues: List[str] = []

        if rule_name in seen_names:
            issues.append(f"Duplicate rule name '{rule_name}' also declared in {seen_names[rule_name]}")
        else:
            seen_names[rule_name] = yaral_file.name

        fp = _normalize_events_fingerprint(raw)
        if fp:
            if fp in seen_fingerprints:
                issues.append(
                    f"Duplicate events: logic fingerprint ({fp}) matches {seen_fingerprints[fp]}"
                )
            else:
                seen_fingerprints[fp] = yaral_file.name

        if not MITRE_META_RE.search(raw):
            issues.append("Missing MITRE ATT&CK tactic/technique metadata in meta: section")

        if RESERVED_COUNT_RE.search(raw):
            issues.append("Uses reserved YARA-L outcome identifier '$count' (use '$event_count')")

        if PERL_NOCASE_FLAG_RE.search(raw):
            issues.append("Uses unsupported '/pattern/i' modifier (use '/pattern/ nocase')")

        for dead_lt in dead_refs:
            issues.append(
                f"References dead/silent log source '{dead_lt}' — rule currently cannot fire"
            )

        findings.append(
            StaticRuleAuditFinding(
                file_path=yaral_file.name,
                rule_name=rule_name,
                referenced_log_types=log_types,
                dead_log_types=dead_refs,
                issues=issues,
            )
        )

    return findings
