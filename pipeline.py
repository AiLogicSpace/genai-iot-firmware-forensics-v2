"""
pipeline.py
------------
Orchestrates the full firmware forensics pipeline:

    load firmware -> entropy scan -> string extraction -> secret flagging
    -> component/version detection -> vulnerability cross-reference
    -> GenAI narrative report

Run directly:
    python pipeline.py sample_data/sample_firmware.bin
"""

import argparse
import json
import sys
from pathlib import Path

from core.entropy_analysis import scan_firmware, summarize_high_entropy_regions
from core.string_extractor import extract_ascii_strings, flag_secrets, get_flagged_only
from core.vuln_signatures import find_component_versions, cross_reference
from core.genai_report import build_findings_payload, call_llm


def run_pipeline(firmware_path: str, api_key: str = None) -> dict:
    path = Path(firmware_path)
    if not path.exists():
        raise FileNotFoundError(f"Firmware image not found: {firmware_path}")

    data = path.read_bytes()

    # 1. Entropy analysis
    windows = scan_firmware(data, window_size=512, stride=512)
    high_entropy_regions = summarize_high_entropy_regions(windows)

    # 2. String extraction + secret flagging
    strings = extract_ascii_strings(data)
    strings = flag_secrets(strings)
    flagged_strings = get_flagged_only(strings)

    # 3. Component/version detection + vulnerability cross-reference
    all_string_values = [s.value for s in strings]
    component_matches = find_component_versions(all_string_values)
    vuln_matches = cross_reference(component_matches)

    # 4. Build payload + generate narrative report
    payload = build_findings_payload(high_entropy_regions, flagged_strings, vuln_matches)
    narrative = call_llm(payload, api_key=api_key)

    return {
        "firmware_file": str(path),
        "file_size_bytes": len(data),
        "high_entropy_regions": high_entropy_regions,
        "flagged_strings": [{"offset": s.offset, "value": s.value, "flags": s.flags} for s in flagged_strings],
        "vulnerable_components": vuln_matches,
        "narrative_report": narrative,
    }


def main():
    parser = argparse.ArgumentParser(description="GenAI-Powered IoT Firmware Forensics Platform")
    parser.add_argument("firmware_path", help="Path to firmware binary image")
    parser.add_argument("--api-key", default=None, help="Anthropic API key (optional; falls back to offline mode)")
    parser.add_argument("--json-out", default=None, help="Optional path to save full JSON results")
    args = parser.parse_args()

    results = run_pipeline(args.firmware_path, api_key=args.api_key)

    print("=" * 70)
    print(f"Firmware analyzed: {results['firmware_file']} ({results['file_size_bytes']} bytes)")
    print("=" * 70)
    print(results["narrative_report"])
    print("=" * 70)

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2))
        print(f"\nFull structured results saved to: {args.json_out}")


if __name__ == "__main__":
    sys.exit(main())
