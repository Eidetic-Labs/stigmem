#!/usr/bin/env python3
"""Umbrella release-readiness gate.

This check answers a single question before a publish workflow tags an immutable
release: is the surrounding bookkeeping consistent with the code we are about to
ship?

It does three things existing gates (`check_version_consistency.py`,
`validate_version_surfaces.py`, `check_release_evidence.py`) do not:

1. **CHANGELOG presence and non-emptiness.** When run without `--tag`, asserts
   that `CHANGELOG.md` has a `## [Unreleased]` section with at least one
   non-empty bullet under any subsection — catches the "No unreleased changes"
   lie that lets feature commits land without a CHANGELOG entry. When run with
   `--tag vX.Y.Z`, asserts that a `## [X.Y.Z]` section exists and has body
   content (so a tag push cannot create a CHANGELOG-less release).

2. **Plugin catalog consistency.** Asserts that README plugin entries,
   meta-package extras, and docs catalog pages agree on the published plugin
   package set.

3. **Milestone is closed.** When run with `--tag vX.Y.Z`, asserts that a
   GitHub milestone with title matching the tag's version exists and has zero
   open issues. Requires `gh` CLI on PATH and authenticated for the target repo
   (defaults to `Eidetic-Labs/stigmem`; override with `--repo`). The milestone
   check is skipped if `--no-milestone-check` is passed or if `gh` is missing,
   so the gate still works in environments without GitHub credentials (CI
   passes `gh` in by default).

Exit code 0 if ready, 1 with a diagnostic if not. Intended to be wired into
`.github/workflows/publish.yml` immediately before the tag-gated publish jobs.

Discipline anchor: this gate exists because the v0.9.0a1/a2 release cycle and
the parallel Craik v0.2.0 / v0.3.0 cycles repeatedly surfaced two failure modes
that the existing per-artifact gates do not catch: CHANGELOG sections that
describe the wrong release, and milestones with open issues that should have
shipped in the tagged release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
PLUGIN_CATALOG_CHECK = REPO_ROOT / "scripts" / "check_plugin_readme_pypi_consistency.py"
EVAL_FAST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "eval-fast.yml"
EVAL_RESULTS_DIR = REPO_ROOT / "eval" / "results"

DEFAULT_REPO = "Eidetic-Labs/stigmem"
EXPECTED_ADVERSARIAL_COUNTS = {
    "typo_squatted": 20,
    "contradiction_floods": 9,
    "tombstone_bypass": 10,
    "capability_token": 15,
    "sanitizer_bypass": 25,
}
EXPECTED_RECALL_PROBES = 400
EXPECTED_EVAL_FAST_FILTERS = {
    ".github/workflows/eval-fast.yml",
    "Makefile",
    "eval/**",
    "experimental/eval-harness/**",
    "features/eval-harness/**",
    "node/**",
    "sdks/stigmem-py/**",
    "scripts/validate_adversarial_corpus.py",
    "scripts/validate_adversarial_results.py",
    "spec/**",
    "data/conformance/**",
}
ALLOWED_TRACKED_EVAL_RESULTS = {
    "eval/results/.gitkeep",
    "eval/results/ci-0b1a76a.json",
    "eval/results/ci-0b1a76a.md",
}

VERSION_TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+(?:[ab]\d+|rc\d+)?)$")


def _read_changelog() -> str:
    if not CHANGELOG.exists():
        print(f"FAIL: {CHANGELOG.relative_to(REPO_ROOT)} is missing", file=sys.stderr)
        sys.exit(1)
    return CHANGELOG.read_text()


def _extract_section(changelog: str, heading_pattern: str) -> str | None:
    """Return the body of the first `## <heading>` section, or None if missing.

    Body ends at the next `## ` heading or end of file. Leading/trailing blank
    lines are stripped.
    """
    lines = changelog.splitlines()
    in_section = False
    body: list[str] = []
    # Allow optional trailing content after the bracketed heading (date,
    # em-dash status, etc.). Common CHANGELOG patterns:
    #   `## [Unreleased]`
    #   `## [0.9.0a2] — 2026-05-18`
    #   `## [0.9.0a1] - 2026-05-08`
    head_re = re.compile(rf"^## {heading_pattern}(?:\s.*)?$", re.IGNORECASE)
    for line in lines:
        if head_re.match(line):
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section:
            body.append(line)
    if not in_section:
        return None
    return "\n".join(body).strip()


def _section_has_substantive_content(body: str) -> bool:
    """A section is substantive if it has at least one non-empty bullet.

    Empty placeholders like `_No unreleased changes._` or solitary "—" markers
    do not count.
    """
    if not body:
        return False
    placeholder_re = re.compile(
        r"^\s*[_*]?\s*(no unreleased changes|tbd|n/a|none)\b", re.IGNORECASE
    )
    bullet_re = re.compile(r"^\s*[-*]\s+\S")
    for line in body.splitlines():
        if placeholder_re.match(line):
            return False
        if bullet_re.match(line):
            return True
    return False


def _check_changelog_unreleased(changelog: str) -> list[str]:
    body = _extract_section(changelog, r"\[Unreleased\]")
    if body is None:
        return [
            "CHANGELOG.md is missing a `## [Unreleased]` section. Add one above "
            "the most recent versioned section."
        ]
    if not _section_has_substantive_content(body):
        return [
            "CHANGELOG.md `[Unreleased]` section is empty or contains only a "
            "placeholder. Document landed-but-unreleased changes before tagging."
        ]
    return []


def _check_changelog_for_version(changelog: str, version: str) -> list[str]:
    pattern = rf"\[{re.escape(version)}\]"
    body = _extract_section(changelog, pattern)
    if body is None:
        return [
            f"CHANGELOG.md is missing a `## [{version}]` section. Promote "
            "the `[Unreleased]` section to a `[<version>]` heading before tagging."
        ]
    if not _section_has_substantive_content(body):
        return [
            f"CHANGELOG.md `[{version}]` section has no substantive bullets. "
            "A tagged release must document what shipped."
        ]
    return []


def _check_plugin_catalog_consistency() -> list[str]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(PLUGIN_CATALOG_CHECK)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return []
    detail = result.stderr.strip() or result.stdout.strip()
    return [f"plugin catalog consistency failed: {detail}"]


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise AssertionError(f"{path.relative_to(REPO_ROOT)} is missing") from None
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{path.relative_to(REPO_ROOT)} is invalid JSON: {exc}") from exc


def _load_json_or_failure(path: Path, failures: list[str]) -> object | None:
    try:
        return _load_json(path)
    except AssertionError as exc:
        failures.append(str(exc))
        return None


def _canonical_corpus_sha(probes: object) -> str:
    raw = json.dumps(probes, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _tracked_files_under(path: Path) -> set[str]:
    result = subprocess.run(  # noqa: S603
        ["git", "ls-files", "--", str(path.relative_to(REPO_ROOT))],  # noqa: S607
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AssertionError(f"could not inspect tracked eval results: {detail}")
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _check_eval_harness_static_gates() -> list[str]:
    failures: list[str] = []

    corpus_dir = REPO_ROOT / "eval" / "corpus" / "adversarial"
    total = 0
    for class_name, expected_count in EXPECTED_ADVERSARIAL_COUNTS.items():
        class_total = 0
        for path in sorted((corpus_dir / class_name).glob("*.json")):
            data = _load_json_or_failure(path, failures)
            if data is None:
                continue
            class_total += len(data) if isinstance(data, list) else 1
        if class_total != expected_count:
            failures.append(
                f"eval adversarial corpus {class_name!r} has {class_total} "
                f"scenario(s), expected {expected_count}"
            )
        total += class_total
    expected_total = sum(EXPECTED_ADVERSARIAL_COUNTS.values())
    if total != expected_total:
        failures.append(
            f"eval adversarial corpus has {total} scenario(s), expected {expected_total}"
        )

    probes_path = REPO_ROOT / "eval" / "corpus" / "recall" / "probes.json"
    probes = _load_json_or_failure(probes_path, failures)
    if not isinstance(probes, list):
        failures.append("eval recall probes.json must contain a JSON list")
        probes = []
    elif len(probes) != EXPECTED_RECALL_PROBES:
        failures.append(
            f"eval recall corpus has {len(probes)} probe(s), "
            f"expected {EXPECTED_RECALL_PROBES}"
        )

    baseline_path = REPO_ROOT / "eval" / "corpus" / "recall" / "baseline.json"
    baseline = _load_json_or_failure(baseline_path, failures)
    if not isinstance(baseline, dict):
        failures.append("eval recall baseline.json must contain a JSON object")
    else:
        required = {"nDCG@10", "Recall@5", "corpus_sha", "server_version", "recorded_at"}
        missing = sorted(required - set(baseline))
        if missing:
            failures.append(f"eval recall baseline.json missing key(s): {', '.join(missing)}")
        expected_sha = _canonical_corpus_sha(probes)
        if baseline.get("corpus_sha") != expected_sha:
            failures.append(
                "eval recall baseline corpus_sha "
                f"{baseline.get('corpus_sha')!r} does not match {expected_sha!r}"
            )

    workflow_text = EVAL_FAST_WORKFLOW.read_text(encoding="utf-8")
    missing_filters = sorted(
        token for token in EXPECTED_EVAL_FAST_FILTERS if f'- "{token}"' not in workflow_text
    )
    if missing_filters:
        failures.append(
            "eval-fast workflow is missing path filter(s): " + ", ".join(missing_filters)
        )

    tracked_results = _tracked_files_under(EVAL_RESULTS_DIR)
    unexpected_results = sorted(tracked_results - ALLOWED_TRACKED_EVAL_RESULTS)
    if unexpected_results:
        failures.append(
            "eval/results contains tracked generated artifact(s) outside the "
            "allowlist: " + ", ".join(unexpected_results)
        )

    return failures


def _run_gh_api(repo: str, path: str) -> tuple[bool, str]:
    if not shutil.which("gh"):
        return False, "gh CLI not on PATH"
    try:
        result = subprocess.run(  # noqa: S603
            ["gh", "api", f"repos/{repo}/{path}"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return False, f"gh invocation failed: {exc}"
    if result.returncode != 0:
        return False, f"gh api error: {result.stderr.strip() or result.stdout.strip()}"
    return True, result.stdout


def _check_milestone(repo: str, version: str) -> list[str]:
    ok, payload = _run_gh_api(repo, "milestones?state=all&per_page=100")
    if not ok:
        return [
            f"could not query milestones for {repo}: {payload}. "
            "Re-run with `--no-milestone-check` to skip this gate locally."
        ]
    try:
        milestones = json.loads(payload)
    except json.JSONDecodeError as exc:
        return [f"could not parse milestones payload: {exc}"]
    target_titles = {f"v{version}", version}
    matches = [m for m in milestones if m.get("title") in target_titles]
    if not matches:
        return [
            f"no milestone with title matching {sorted(target_titles)} found on "
            f"{repo}. Create one (see CONTRIBUTING.md §PR-closes-issue and "
            "milestone discipline) or skip this gate with "
            "`--no-milestone-check`."
        ]
    failures: list[str] = []
    for milestone in matches:
        open_count = milestone.get("open_issues", 0)
        if open_count:
            number = milestone.get("number")
            url = milestone.get("html_url", "")
            failures.append(
                f"milestone {milestone['title']!r} (#{number}) has "
                f"{open_count} open issue(s) — close or move them before "
                f"tagging. {url}".rstrip()
            )
    return failures


def _print_failures(failures: Iterable[str]) -> None:
    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        help=(
            "Release tag being prepared (e.g. v0.9.0a3). When provided, "
            "switches CHANGELOG check to the versioned section and runs the "
            "milestone gate. Without --tag, only the `[Unreleased]` non-empty "
            "check runs."
        ),
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help=f"GitHub repo for milestone lookup (default: {DEFAULT_REPO}).",
    )
    parser.add_argument(
        "--no-milestone-check",
        action="store_true",
        help="Skip the milestone gate. Useful for local checks without gh auth.",
    )
    args = parser.parse_args(argv)

    failures: list[str] = []
    changelog = _read_changelog()

    if args.tag:
        match = VERSION_TAG_RE.match(args.tag)
        if not match:
            print(
                f"FAIL: --tag {args.tag!r} does not match vMAJOR.MINOR.PATCH"
                "[aN|bN|rcN]",
                file=sys.stderr,
            )
            return 1
        version = match.group("version")
        failures.extend(_check_changelog_for_version(changelog, version))
        if not args.no_milestone_check:
            failures.extend(_check_milestone(args.repo, version))
    else:
        failures.extend(_check_changelog_unreleased(changelog))
    failures.extend(_check_plugin_catalog_consistency())
    failures.extend(_check_eval_harness_static_gates())

    if failures:
        _print_failures(failures)
        return 1

    print("OK: release readiness checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
