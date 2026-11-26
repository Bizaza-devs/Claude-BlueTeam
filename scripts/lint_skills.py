#!/usr/bin/env python3
"""Lint the claude-blueteam bundle.

Checks
  skills/*/SKILL.md  frontmatter present, only name+description, name == folder,
                     description length, body length, required sections,
                     backticked cross-references point at real skills
  commands/*.md      frontmatter with description
  agents/*.md        frontmatter with name (== file stem) and description
  catalogue          every skill in CONTRIBUTING.md exists and vice versa

Exit code 1 on any error. Warnings do not fail the run.
Usage: python scripts/lint_skills.py [--strict]   (--strict turns warnings into errors)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_SECTIONS = ["## When to use", "## Ground rules", "## Workflow", "## Output"]
MIN_LINES, MAX_LINES = 150, 600
DESC_MIN, DESC_MAX = 150, 1024

errors: list[str] = []
warnings: list[str] = []


def frontmatter(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    fm: dict[str, str] = {}
    key = None
    for line in text[3:end].strip("\n").splitlines():
        m = re.match(r"^([A-Za-z_-]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            fm[key] = m.group(2).strip().strip('"').strip("'")
        elif key and line.startswith((" ", "\t")):
            fm[key] += " " + line.strip()
    return fm, text[end + 4 :]


def catalogue() -> set[str]:
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    block = text.split("## Skill catalogue", 1)[1].split("\n## ", 1)[0]
    return set(re.findall(r"`([a-z0-9-]+)`", block))


def lint_skills() -> set[str]:
    names: set[str] = set()
    for skill in sorted((ROOT / "skills").glob("*/SKILL.md")):
        rel = skill.relative_to(ROOT)
        folder = skill.parent.name
        names.add(folder)
        fm, body = frontmatter(skill)
        if not fm:
            errors.append(f"{rel}: missing YAML frontmatter")
            continue
        extra = set(fm) - {"name", "description"}
        if extra:
            errors.append(f"{rel}: non-portable frontmatter keys {sorted(extra)}")
        if fm.get("name") != folder:
            errors.append(f"{rel}: name '{fm.get('name')}' != folder '{folder}'")
        d = fm.get("description", "")
        if not (DESC_MIN <= len(d) <= DESC_MAX):
            errors.append(f"{rel}: description length {len(d)} outside {DESC_MIN}-{DESC_MAX}")
        lines = body.count("\n")
        if lines < MIN_LINES or lines > MAX_LINES:
            warnings.append(f"{rel}: {lines} body lines (target {MIN_LINES}-{MAX_LINES})")
        for sec in REQUIRED_SECTIONS:
            if not re.search(rf"^{re.escape(sec)}", body, re.M):
                errors.append(f"{rel}: missing section '{sec}'")
    return names


def lint_crossrefs(names: set[str]) -> None:
    pattern = re.compile(r"`((?:hunt|ir|hardening)-[a-z0-9-]+)`")
    files = list((ROOT / "skills").glob("*/SKILL.md")) + list((ROOT / "commands").glob("*.md")) + list(
        (ROOT / "agents").glob("*.md")
    )
    for f in files:
        for ref in set(pattern.findall(f.read_text(encoding="utf-8"))):
            if ref not in names:
                errors.append(f"{f.relative_to(ROOT)}: reference to unknown skill `{ref}`")


def lint_commands_agents() -> None:
    for cmd in sorted((ROOT / "commands").glob("*.md")):
        fm, _ = frontmatter(cmd)
        if not fm.get("description"):
            errors.append(f"{cmd.relative_to(ROOT)}: missing description")
    for agent in sorted((ROOT / "agents").glob("*.md")):
        fm, _ = frontmatter(agent)
        if fm.get("name") != agent.stem:
            errors.append(f"{agent.relative_to(ROOT)}: name '{fm.get('name')}' != file '{agent.stem}'")
        if not fm.get("description"):
            errors.append(f"{agent.relative_to(ROOT)}: missing description")


def main() -> int:
    strict = "--strict" in sys.argv
    names = lint_skills()
    cat = catalogue()
    for missing in sorted(cat - names):
        errors.append(f"catalogue skill '{missing}' has no skills/{missing}/SKILL.md")
    for extra in sorted(names - cat):
        errors.append(f"skills/{extra} is not in the CONTRIBUTING.md catalogue")
    lint_crossrefs(names)
    lint_commands_agents()

    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    n_cmd = len(list((ROOT / "commands").glob("*.md")))
    n_ag = len(list((ROOT / "agents").glob("*.md")))
    print(f"\n{len(names)} skills, {n_cmd} commands, {n_ag} agents - {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors or (strict and warnings) else 0


if __name__ == "__main__":
    sys.exit(main())
