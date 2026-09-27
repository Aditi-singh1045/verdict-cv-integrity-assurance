VERDICT — SIH 2026 FINAL DEMO PROTOTYPE

1. Open PowerShell in this folder.
2. If PowerShell blocks scripts, run:
   powershell -ExecutionPolicy Bypass -File .\run_prototype.ps1
3. Open:
   http://127.0.0.1:8765/

Demo flow:
WELCOME → SIGN IN → COMMAND CENTER → CASE INTAKE → PROCESS → ASSURANCE REPORT

The product concept is: contributor material → full-pipeline investigation → evidence dossier → trust assessment → disposition → audit.

The Scenario Lab is a controlled demonstration harness. It injects a known synthetic test condition so the workflow can be reproduced; the condition is not the final verdict.

The prototype is local/offline and uses deterministic synthetic scenarios.
No cloud APIs, external runtime services, online LLM, or remote blockchain are required.

Demo credentials are intentionally not hard-coded in the UI; enter any Analyst ID and Access Key for the prototype access screen.
