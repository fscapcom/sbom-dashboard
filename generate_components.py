#!/usr/bin/env python3
import json
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
SBOM_ROOT = BASE_DIR / "sboms"
OUTPUT_DIR = BASE_DIR / "data"
OUTPUT_FILE = OUTPUT_DIR / "components.json"


def find_sbom_files(root: Path) -> List[Path]:
    """Recursively find all JSON files under the SBOM root."""
    return [p for p in root.rglob("*.json") if p.is_file()]


def extract_components_from_sbom(sbom_path: Path) -> List[Dict[str, Any]]:
    """
    Extract components from a CycloneDX-style SBOM (JSON).
    Returns a list of component dicts with some normalized fields.
    """
    try:
        with sbom_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to read SBOM {sbom_path}: {e}")
        return []

    components = data.get("components", [])
    metadata = data.get("metadata", {})
    meta_component = metadata.get("component", {})

    project_name = meta_component.get("name") or infer_project_name_from_path(sbom_path)
    project_version = meta_component.get("version", "")
    project_group = meta_component.get("group", "")

    results: List[Dict[str, Any]] = []
    for c in components:
        name = c.get("name", "")
        version = c.get("version", "")
        group = c.get("group", "")
        purl = c.get("purl", "")
        c_type = c.get("type", "")
        licenses: List[str] = []

        for l in c.get("licenses", []) or []:
            lic = l.get("license", {})
            if isinstance(lic, dict):
                lic_id = lic.get("id") or lic.get("name")
                if lic_id:
                    licenses.append(lic_id)

        results.append(
            {
                "project_name": project_name,
                "project_version": project_version,
                "project_group": project_group,
                "sbom_path": sbom_path.relative_to(SBOM_ROOT).as_posix(),
                "component_name": name,
                "component_version": version,
                "component_group": group,
                "component_type": c_type,
                "purl": purl,
                "licenses": licenses,
            }
        )

    return results


def infer_project_name_from_path(sbom_path: Path) -> str:
    """Fallback: derive a project name from the SBOM path."""
    try:
        rel = sbom_path.relative_to(SBOM_ROOT)
    except ValueError:
        return sbom_path.stem

    parts = list(rel.parts)
    if parts:
        parts[-1] = Path(parts[-1]).stem
    return "/".join(parts)


def main():
    # Debug-Ausgabe, um sicher zu sein, dass die Pfade stimmen
    print(f"[DEBUG] __file__     = {__file__}")
    print(f"[DEBUG] BASE_DIR    = {BASE_DIR}")
    print(f"[DEBUG] SBOM_ROOT   = {SBOM_ROOT}")
    print(f"[DEBUG] OUTPUT_FILE = {OUTPUT_FILE}")

    if not SBOM_ROOT.exists():
        raise SystemExit(f"SBOM root directory does not exist: {SBOM_ROOT}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_components: List[Dict[str, Any]] = []

    sbom_files = find_sbom_files(SBOM_ROOT)
    print(f"[INFO] Found {len(sbom_files)} SBOM file(s) under {SBOM_ROOT}")

    for sbom in sbom_files:
        comps = extract_components_from_sbom(sbom)
        print(f"[INFO] {sbom}: extracted {len(comps)} components")
        all_components.extend(comps)

    all_components.sort(key=lambda x: (x["project_name"], x["component_name"], x["component_version"]))

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(all_components, f, indent=2)

    print(f"[INFO] Wrote {len(all_components)} components to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
