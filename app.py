"""
app.py
-------
Streamlit dashboard for the GenAI-Powered IoT Vulnerability &
Firmware Forensics Platform.

Run with:
    streamlit run app.py

Upload any firmware binary (.bin) or use the bundled synthetic sample
to see entropy mapping, flagged secrets, vulnerability cross-reference,
and a GenAI-generated narrative report, all in one view.
"""

import json
import os
import tempfile

import streamlit as st

from core.entropy_analysis import scan_firmware, summarize_high_entropy_regions
from core.string_extractor import extract_ascii_strings, flag_secrets, get_flagged_only
from core.vuln_signatures import find_component_versions, cross_reference
from core.genai_report import build_findings_payload, call_llm

st.set_page_config(page_title="Firmware Forensics Platform", layout="wide")

st.title("🔍 GenAI-Powered IoT Vulnerability & Firmware Forensics Platform")
st.caption("A CBSE/IIT Guwahati Pragyan AI research submission — static forensic analysis "
           "of IoT firmware images with GenAI-assisted reporting.")

with st.sidebar:
    st.header("Input")
    uploaded = st.file_uploader("Upload a firmware image (.bin)", type=["bin", "img", "fw"])
    use_sample = st.checkbox("Use bundled synthetic sample instead", value=uploaded is None)
    api_key = st.text_input("Anthropic API key (optional — leave blank for offline mode)", type="password")
    run_button = st.button("Run Forensic Analysis", type="primary")

if run_button:
    if use_sample:
        sample_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample_firmware.bin")
        if not os.path.exists(sample_path):
            st.error("Sample firmware not found. Run `python sample_data/generate_sample.py` first.")
            st.stop()
        data = open(sample_path, "rb").read()
        st.info(f"Analyzing bundled synthetic sample ({len(data)} bytes)")
    elif uploaded is not None:
        data = uploaded.read()
        st.info(f"Analyzing uploaded file: {uploaded.name} ({len(data)} bytes)")
    else:
        st.warning("Please upload a firmware file or select the sample option.")
        st.stop()

    with st.spinner("Running entropy scan, string extraction, and vulnerability cross-reference..."):
        windows = scan_firmware(data, window_size=512, stride=512)
        high_entropy_regions = summarize_high_entropy_regions(windows)

        strings = extract_ascii_strings(data)
        strings = flag_secrets(strings)
        flagged_strings = get_flagged_only(strings)

        all_values = [s.value for s in strings]
        component_matches = find_component_versions(all_values)
        vuln_matches = cross_reference(component_matches)

        payload = build_findings_payload(high_entropy_regions, flagged_strings, vuln_matches)
        narrative = call_llm(payload, api_key=api_key or None)

    col1, col2, col3 = st.columns(3)
    col1.metric("High-Entropy Regions", len(high_entropy_regions))
    col2.metric("Flagged Strings", len(flagged_strings))
    col3.metric("Known-Vulnerable Components", len(vuln_matches))

    st.subheader("📈 Entropy Map")
    chart_data = {"offset": [w.offset for w in windows], "entropy": [w.entropy for w in windows]}
    st.line_chart(chart_data, x="offset", y="entropy")
    st.caption("Spikes above ~6.5 bits/byte indicate likely compressed, encrypted, or packed regions.")

    st.subheader("🚩 Flagged Strings (possible secrets / debug artifacts)")
    if flagged_strings:
        st.table([{"offset": s.offset, "value": s.value, "flags": ", ".join(s.flags)} for s in flagged_strings])
    else:
        st.success("No flagged strings detected in this sample.")

    st.subheader("🛡️ Known-Vulnerable Component Matches")
    if vuln_matches:
        for v in vuln_matches:
            with st.expander(f"{v['component']} {v['version']} — {v['cve_reference']}"):
                st.write(f"**Risk summary:** {v['risk_summary']}")
                st.write(f"**Remediation:** {v['remediation']}")
    else:
        st.success("No known-vulnerable component signatures matched.")

    st.subheader("📝 GenAI-Generated Narrative Report")
    st.text(narrative)

    st.download_button(
        "Download full JSON results",
        data=json.dumps({
            "high_entropy_regions": high_entropy_regions,
            "flagged_strings": [{"offset": s.offset, "value": s.value, "flags": s.flags} for s in flagged_strings],
            "vulnerable_components": vuln_matches,
            "narrative_report": narrative,
        }, indent=2),
        file_name="firmware_forensic_report.json",
        mime="application/json",
    )
else:
    st.info("Configure inputs in the sidebar and click **Run Forensic Analysis** to begin.")
