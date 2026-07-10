# GenAI-Powered IoT Vulnerability & Firmware Forensics Platform

A student research submission (Pragyan AI, IIT Guwahati) demonstrating a
working static-analysis pipeline for IoT firmware forensics, with an
optional GenAI narration layer for human-readable reporting.

## What this actually does

1. **Entropy analysis** — scans the firmware byte-by-byte in windows to
   locate likely compressed/encrypted regions (a real forensic technique
   used by tools like Binwalk).
2. **String extraction + secret flagging** — pulls printable strings and
   flags patterns that commonly indicate hardcoded credentials, private
   keys, or leftover debug services.
3. **Vulnerability signature matching** — detects known component/version
   strings (BusyBox, Dropbear, OpenSSL, U-Boot) and cross-references a
   small curated table of historically documented CVE classes.
4. **GenAI narrative report** — takes the structured findings above (never
   inventing new ones) and writes a plain-language summary for a report
   or viva. Runs in a deterministic offline mode if no API key is set, so
   the whole project is demonstrable without internet access.

**What this does NOT do:** generate exploits, attack real devices, or
scan live networks. This is a defensive forensics and detection tool only.

## Setup

```bash
pip install -r requirements.txt
python sample_data/generate_sample.py   # builds a synthetic demo firmware
```

## Run the CLI pipeline

```bash
python pipeline.py sample_data/sample_firmware.bin --json-out reports/sample_report.json
```

## Run the interactive dashboard

```bash
streamlit run app.py
```

## Run the test suite

```bash
pytest tests/ -v
```

## Using a real LLM for narration (optional)

```bash
export ANTHROPIC_API_KEY=your_key_here
python pipeline.py sample_data/sample_firmware.bin --api-key $ANTHROPIC_API_KEY
```

Without a key, the pipeline automatically falls back to a deterministic
template-based summary — the analysis itself is unaffected either way.

## Project structure

```
firmware_forensics/
├── core/
│   ├── entropy_analysis.py     # Shannon entropy scanning
│   ├── string_extractor.py     # ASCII strings + secret pattern flags
│   ├── vuln_signatures.py      # component/version → CVE cross-reference
│   └── genai_report.py         # LLM narration layer (+ offline fallback)
├── sample_data/
│   └── generate_sample.py      # builds a synthetic demo firmware image
├── tests/
│   └── test_forensics.py       # pytest suite, 12 tests, all passing
├── pipeline.py                 # CLI entry point
├── app.py                      # Streamlit dashboard
└── requirements.txt
```

## Known limitations (documented honestly for the research paper)

- The vulnerability reference table is small and manually curated for
  demonstration, not a live CVE feed — a production system would connect
  to the NVD API.
- Version comparison is string-based, not full semantic version parsing.
- Entropy analysis flags *candidate* regions for human review; it cannot
  by itself distinguish encryption from ordinary compression.
- Secret-detection regex patterns will miss obfuscated or non-standard
  credential formats — this is a heuristic aid, not a guarantee.
