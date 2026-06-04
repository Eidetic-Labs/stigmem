from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACKER = ROOT / "docs" / "internal" / "plugin-publication-disposition.md"

EXPECTED_DISPOSITIONS = {
    "mcp-adapter": "published",
    "obsidian-adapter": "hold",
    "cognee-adapter": "published",
    "gemini-adapter": "published",
    "letta-adapter": "published",
    "zep-adapter": "published",
    "openai-tools-adapter": "published",
    "paperclip-adapter": "defer",
    "dashboard": "defer",
    "eval-harness": "internal",
    "deploy-fly": "defer",
    "deploy-paas": "defer",
    "deploy-systemd": "defer",
    "deploy-helm": "defer",
    "deploy-grafana": "defer",
}


def _tracker_dispositions() -> dict[str, str]:
    dispositions: dict[str, str] = {}
    for line in TRACKER.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 5 or cells[0] in {"---", "Order", "Surface"}:
            continue
        feature_cell = cells[2]
        disposition_cell = cells[4] if feature_cell.startswith("`features/") else cells[3]
        if not feature_cell.startswith("`features/"):
            feature_cell = cells[1]
        feature = feature_cell.strip("`").removeprefix("features/").strip("/")
        disposition = disposition_cell.strip("`")
        if feature in EXPECTED_DISPOSITIONS:
            dispositions[feature] = disposition
    return dispositions


def _status_disposition(feature: str) -> str:
    status = (ROOT / "features" / feature / "status.md").read_text(encoding="utf-8")
    marker = "| Publication state | `"
    for line in status.splitlines():
        if line.startswith(marker):
            return line.removeprefix(marker).split("`", 1)[0]
    raise AssertionError(f"features/{feature}/status.md is missing Publication state")


def main() -> None:
    tracker_dispositions = _tracker_dispositions()
    if tracker_dispositions != EXPECTED_DISPOSITIONS:
        missing = sorted(set(EXPECTED_DISPOSITIONS) - set(tracker_dispositions))
        unexpected = sorted(set(tracker_dispositions) - set(EXPECTED_DISPOSITIONS))
        mismatched = {
            feature: tracker_dispositions[feature]
            for feature, expected in EXPECTED_DISPOSITIONS.items()
            if tracker_dispositions.get(feature) not in {None, expected}
        }
        raise SystemExit(
            "plugin-publication-disposition: tracker mismatch "
            f"missing={missing} unexpected={unexpected} mismatched={mismatched}"
        )

    status_mismatches = {
        feature: _status_disposition(feature)
        for feature, expected in EXPECTED_DISPOSITIONS.items()
        if _status_disposition(feature) != expected
    }
    if status_mismatches:
        raise SystemExit(
            "plugin-publication-disposition: feature status mismatch "
            f"{status_mismatches}"
        )

    print(
        "plugin-publication-disposition: validated "
        f"{len(EXPECTED_DISPOSITIONS)} publication disposition(s)"
    )


if __name__ == "__main__":
    main()
