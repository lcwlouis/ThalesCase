# ThalesCase

This is a case assignment for Thales Singapore AI Engineering Role. The demo application will require the following submissions:

1. '/specs/' containing the following files:
    - `requirements.md` — clear functional requirements + acceptance criteria
    - `tech-spec.md` — technical choices, architecture, key flows, error handling, security 
    - `verification.md` — how you verified correctness (tests, known vectors, steps)
2. '/app/' containing the following files:
    - Source Code
    - Instructions to run application locally (web) or a simulator (mobile)
3. '/`README.md` '
    — setup and steps to run the application.
    - How to use the UI and application

### Rules / constraints

*   App must run **locally** (no required cloud services).
*   You may use **one AI-assisted coding tool** (Claude Code / Codex CLI / Gemini CLI / GitHub Copilot / Cline / Continue.dev, etc.).
*   You are expected to **review what the AI generates**, fix issues, and explain key decisions in `tech-spec.md` and `verification.md`.

***

# Assignment 1 — Local Web App PoC: Hashing + ECDSA (P‑256)

### Goal

Build a small **local web application** with a simple UI to perform:

1.  **SHA‑256 hashing** of plain text → display hash as **HEX**
2.  **ECC P‑256 keypair generation**, **sign**, and **verify** → display keys + signatures as **HEX**


### Non-functional constraints

*   Runs on a local machine via one of:
    *   static page, or local dev server
*   No external services required
*   Provide reproducible run steps in `README.md`

### Local test configuration

*   `app/settings.example.json` contains optional, non-secret sample values for copy/paste verification.
*   Interviewer-provided keys or signatures should be treated as local test fixtures, not confidential secrets.
*   Local `.env*` files and `app/settings.local.json` are ignored by git for safety.

### Suggested stretch goals (optional)

*   Add known test vectors for SHA‑256 and ECDSA in `verification.md`
*   Add automated tests (unit/integration)
*   Export/import keys (file or copy/paste)

--- 
## What we’re evaluating (high level)

*   Spec quality: clarity, completeness, testability
*   AI instructions: how you guided the assistant and constrained outputs
*   Code review: correctness, security hygiene, maintainability
*   Verification: proof it works (tests + evidence)
