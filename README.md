<h1 align="center">🛡️ VERDICT</h1>
<h3 align="center">Offline Computer-Vision Integrity Assurance Engine</h3>

<p align="center">
  An evidence-first, fully local trust-assessment workspace for multi-contributor
  computer-vision pipelines — investigating data, model, inference, and distribution
  integrity before rendering a verdict.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Runtime" src="https://img.shields.io/badge/Runtime-Offline%20%2F%20Local-1abc9c">
  <img alt="Server" src="https://img.shields.io/badge/Server-Stdlib%20HTTP-informational">
  <img alt="Dependencies" src="https://img.shields.io/badge/External%20APIs-0-brightgreen">
  <img alt="Status" src="https://img.shields.io/badge/status-SIH%202026%20prototype-yellow">
</p>

---

## Overview

**VERDICT** is a local, air-gapped assurance workspace built to answer one question about a computer-vision artifact submitted by an external contributor: *can this data, model, and inference chain be trusted?*

Rather than asking an analyst to guess, VERDICT runs the submitted material through a ten-stage evidence pipeline — checking data integrity, model behavior, inference provenance, and distribution shift — links every finding into a corroborated evidence dossier, cross-examines competing explanations, resolves contradictions, and only then renders a confidence-scored verdict with an operational disposition and a tamper-evident audit trail.

The analyst never selects the outcome. VERDICT investigates the evidence and the evidence determines the verdict.

> **No cloud APIs. No external runtime services. No online LLM. No remote blockchain.**
> The entire engine runs locally, deterministically, and offline — built for demonstration in air-gapped or reproducibility-sensitive environments.

---

## The assurance pipeline

```
WELCOME → SIGN IN → COMMAND CENTER → CASE INTAKE → INVESTIGATE
   → EVIDENCE DOSSIER → CROSS-EXAMINE → CONTRADICTION CHECK
   → TRUST ASSESSMENT → VERDICT → DISPOSITION → AUDIT
```

Four assurance domains are investigated for every case:

| Domain | What it checks |
|---|---|
| **Data integrity** | Exact/near-duplicate detection, label-consistency analysis, trigger-pattern (backdoor) detection |
| **Model integrity** | Artifact identity hashing (SHA-256) and a behavioral reference battery — a white-box fallback used when internal model state is unavailable |
| **Inference provenance** | Image/model/preprocess/output identity verification and sequence/nonce replay detection |
| **Distribution assessment** | Statistical comparison against a trusted reference distribution, with shift treated as *context*, never as proof of compromise |

Every finding is recorded as a structured **Evidence** object (`evidence_id`, `domain`, `detector`, `observation`, `severity`, `confidence`, `status`) with explicit `supports`, `contradicts`, `alternatives`, and `controlled`-examination links — so a single anomaly can never look like proof on its own.

---

## Verdicts & disposition

| Verdict | Meaning | Disposition |
|---|---|---|
| 🟢 **TRUSTWORTHY** | No material anomaly across any domain; behavior and identity checks pass | **ACCEPT** |
| 🟡 **REVIEW** | A measurable anomaly exists but does not, by itself, establish compromise | **HUMAN REVIEW** |
| 🔴 **COMPROMISED** | Decisive, corroborated integrity failure (identity mismatch, replay, anomalous behavior, or trigger pattern) | **QUARANTINE** |

Confidence reflects *confidence in the assessment itself* — not a probability of malicious intent — and every audit event is chained (`previous_hash → record_hash`) so the evidence trail is tamper-evident.

---

## Scenario Lab (reproducible demo conditions)

VERDICT ships with six deterministic synthetic scenarios so the full pipeline can be demonstrated reproducibly without any real dataset:

| Condition | Category | What it injects | Resulting verdict |
|---|---|---|---|
| `TRUSTWORTHY` | Reference | Clean, balanced synthetic dataset | TRUSTWORTHY |
| `REVIEW` | Ambiguous | A handful of locally inconsistent labels | REVIEW |
| `COMPROMISED` | Injected | Backdoor trigger pattern + anomalous model behavior | COMPROMISED |
| `TRIGGER` | Injected | Repeated localized trigger pattern, strong target-label correlation | COMPROMISED |
| `DUPLICATE_FLOOD` | Injected | Concentrated near-duplicate sample flooding | REVIEW |
| `OOD` | Distributional | Out-of-distribution feature shift vs. the trusted reference | REVIEW |

`TRIGGER`, `OOD`, and `DUPLICATE_FLOOD` are **investigated conditions** injected for demonstration — they are not verdicts themselves. `TRUSTWORTHY`, `REVIEW`, and `COMPROMISED` are the three possible **final trust assessments** VERDICT can reach.

---

## Quick start

**Requirements:** Python 3.10+, no external packages, no internet connection.

### Windows

```powershell
# From the project folder:
powershell -ExecutionPolicy Bypass -File .\run_prototype.ps1
```

or double-click `run_prototype.bat`.

### macOS / Linux

```bash
python3 verdict_app.py
```

Then open:

```
http://127.0.0.1:8765/
```

Sign in with **any** Analyst ID and Access Key — the prototype access screen intentionally has no hard-coded credentials.

### Run the test suite

```bash
python -m tests.test_core
```

This validates that every Scenario Lab condition resolves to its expected verdict, disposition, and evidence/audit-chain length.

---

## Demo flow

1. Open the local welcome screen — VERDICT introduces itself as an offline, evidence-based assurance workspace.
2. **Sign in** with any demonstration credentials.
3. In the **Command Center**, review the four assurance domains, the evidence ledger, the six reproducible Scenario Lab conditions, and the ten-stage pipeline.
4. **Start a new investigation** — Case Intake registers contributor material, dataset, model, and inference/output context. The analyst does *not* choose the verdict.
5. Optionally select a **Scenario Lab** condition to inject a known synthetic test case for a reproducible demonstration.
6. Watch the pipeline run stage by stage, live.
7. Review the final **Assurance Report**: trust assessment, confidence, evidence dossier, cross-examination, contradiction check, technical verification, operational disposition, and the tamper-evident audit trail.
8. Click **RUN ANOTHER LAB TEST** to retain case metadata and demonstrate another condition.

---

## Project structure

```
VERDICT_SIH_FINAL_CORRECTED/
├── verdict_app.py            # entry point — starts the local HTTP server
├── run_prototype.ps1         # Windows PowerShell launcher
├── run_prototype.bat         # Windows batch launcher
├── README_RUN.txt            # quick operator run notes
├── src/
│   ├── core.py                # evidence engine: data/model/inference/distribution checks,
│   │                           # verdict logic, cross-examination, contradiction check,
│   │                           # confidence scoring, and the chained audit trail
│   └── server.py               # zero-dependency HTTP server + full HTML/CSS UI
│                                # (welcome, login, command center, intake, processing,
│                                #  case report, JSON API)
├── tests/
│   └── test_core.py           # regression test — verifies verdict/disposition/evidence
│                                # counts for all six Scenario Lab conditions
├── docs/
│   ├── ARCHITECTURE.md        # pipeline & assurance-domain design notes
│   └── DEMO_SCRIPT.md         # step-by-step demo walkthrough
├── reports/                   # generated per-case assurance reports (JSON)
├── audit/                     # generated per-case chained audit trails (JSON)
├── cases/, data/, models/     # runtime working directories
└── __pycache__/               # compiled bytecode (safe to ignore/remove)
```

> **Note on assets:** this project does not currently include a dedicated `assets/` folder (no image, icon, or logo files were found in the archive). The interface's visual identity — the "V" emblem, radar/orbit motif, and dark HUD styling — is generated entirely at runtime as inline CSS inside `src/server.py`, so no static image assets are required to run or brand the app. If a logo or screenshot set is added later, placing it under `assets/` and referencing it here (e.g. `![VERDICT](assets/logo.png)`) is recommended.

---

## API access

Every case is also available as raw JSON, useful for integration or automated grading:

```
GET /api/case?scenario=COMPROMISED   # single case report
GET /api/cases                       # all six scenario reports
```

Pre-generated report and audit snapshots are also available directly in [`reports/`](reports) and [`audit/`](audit) for each of the `DEMO-*` and `TEST-*` case IDs.

---

## Design principles

- **Evidence over assertion.** Every claim is backed by a structured `Evidence` record with severity, confidence, and explicit relationships to other evidence (`supports`, `contradicts`, `alternatives`, `controlled`).
- **Shift is context, not proof.** A detected distribution shift alone never triggers a COMPROMISED verdict — it is weighed alongside provenance and behavioral evidence.
- **Competing explanations are tested, not dismissed.** The cross-examination stage explicitly asks whether legitimate explanations (sensor, terrain, season, acquisition variance) could account for an anomaly before it is treated as evidence of compromise.
- **Tamper-evident by construction.** Every evidence event is hashed and chained (`previous_hash → record_hash`), producing a verifiable local audit trail without any external ledger or blockchain service.
- **Deterministic and reproducible.** All Scenario Lab conditions use a fixed seed, so the same condition always produces the same evidence, verdict, and audit chain — critical for demonstration and grading.

---

## Known limitations (declared, not hidden)

- Deterministic synthetic scenarios are used for reproducibility — this is a prototype, not a production forensics tool.
- Distribution shift is explicitly *not* treated as proof of compromise.
- White-box model analysis (parameter/activation access) is unavailable in this prototype; a behavioral-probe fallback is used instead, and this limitation is surfaced directly in the evidence dossier.
- Operational thresholds (behavioral distance, shift normalization, duplicate distance) are demonstration defaults and require validation against real trusted reference data before any production use.

---

## Context

**Project:** VERDICT — Computer Vision Integrity Assurance Engine
**Context:** Smart India Hackathon (SIH) 2026 — Final Demo Prototype
**Author:** Aditi Singh
**Collaborator:**
