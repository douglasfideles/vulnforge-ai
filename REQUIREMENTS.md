# VulnForge AI — Software Requirements Specification

**Version:** 1.0 · **Status:** Implementation-ready · **License:** GPL-3.0-or-later
**Audience:** A developer or AI model implementing VulnForge AI from scratch, without access to the existing source tree.

This document is **self-contained**: every requirement below is stated precisely enough to be
implemented without reading the reference code. It is organized in two parts:

- **Part I — SRS**: numbered functional (RF) and non-functional (RNF) requirements.
- **Part II — Implementation Appendix**: exact data contracts, CLI behavior, sandbox rules,
  lookup tables, project layout, and acceptance criteria.

---

## Table of Contents

- [Part I — Software Requirements Specification](#part-i--software-requirements-specification)
  - [1. Introduction](#1-introduction)
  - [2. Overall Description](#2-overall-description)
  - [3. Functional Requirements](#3-functional-requirements)
  - [4. Non-Functional Requirements](#4-non-functional-requirements)
- [Part II — Implementation Appendix](#part-ii--implementation-appendix)
  - [A. Data Models](#a-data-models)
  - [B. Configuration](#b-configuration)
  - [C. Persistence (SQLite)](#c-persistence-sqlite)
  - [D. CLI Contract (`protoforge`)](#d-cli-contract-protoforge)
  - [E. Threat Analysis Contract](#e-threat-analysis-contract)
  - [F. Scenario Generation Tables](#f-scenario-generation-tables)
  - [G. Scenario Runner & Effect Validation](#g-scenario-runner--effect-validation)
  - [H. Protocol Plugin System](#h-protocol-plugin-system)
  - [I. Attack Synthesis & Codegen Sandbox](#i-attack-synthesis--codegen-sandbox)
  - [J. Dataset Building & IDS Training](#j-dataset-building--ids-training)
  - [K. Reporting](#k-reporting)
  - [L. Optional HTTP API](#l-optional-http-api)
  - [M. Project Layout & Dependencies](#m-project-layout--dependencies)
  - [N. Acceptance Criteria](#n-acceptance-criteria)

---

# Part I — Software Requirements Specification

## 1. Introduction

### 1.1 Purpose

VulnForge AI is an **academic cybersecurity research tool** for emerging IoT publish/subscribe
protocols (**DDS, XRCE-DDS, Zenoh**). It transforms vulnerability records into **controlled
laboratory scenarios**, captures the resulting network traffic, produces **labeled datasets**, and
trains **baseline IDS (Intrusion Detection System) models**. The goal is reproducible, citable
experiments — not offensive tooling.

### 1.2 Scope

The system implements a seven-stage pipeline:

```
vuln → analysis (LLM/rules) → scenario YAML → execute + capture → dataset → IDS → report
```

Around that pipeline it also provides: a pluggable protocol subsystem, LLM-assisted attack
synthesis constrained by an AST sandbox, an effect-validation harness, a command-line interface,
and an optional read-only HTTP API.

### 1.3 Intended Audience

Security researchers running experiments in an **isolated lab**. There is no multi-user support,
authentication, or frontend in this MVP.

### 1.4 Ethical & Safety Framing (normative)


- "Exploit synthesis" is the **parameterization of known technique classes**
  (flood/fuzz/replay/oversized/malformed/injection) guided by a CVE description — **not** 0-day
  generation. LLM-generated code is confined to a byte-payload transformation validated by a
  sandbox (RF-30..RF-34).
- Distributed under **GPL-3.0-or-later**.

### 1.5 Definitions & Acronyms

| Term | Meaning |
|---|---|
| **DDS** | Data Distribution Service — OMG pub/sub middleware (RTPS wire protocol). |
| **RTPS** | Real-Time Publish-Subscribe — DDS wire protocol; header magic `RTPS` = `0x52 0x54 0x50 0x53`. |
| **XRCE-DDS** | DDS For eXtremely Resource-Constrained Environments (eProsima Micro XRCE-DDS Agent). Default UDP 8888. |
| **Zenoh** | Eclipse Zenoh pub/sub/query protocol. Default TCP 7447. |
| **IDS** | Intrusion Detection System (here: baseline ML classifiers). |
| **PCAP** | Packet capture file (`.pcap` / `.pcapng`). |
| **CICFlowMeter** | External tool that extracts per-flow features from a PCAP into CSV. |
| **Baseline message** | Bytes of a *valid* protocol message produced by a protocol plugin. |
| **Mutator** | A sandboxed function `mutate(baseline, seq, rng, urandom) -> bytes` that turns a baseline message into a malicious variant. |
| **Flow** | A row of network-flow features (one connection/aggregate), the unit of the dataset. |
| **Run** | One execution (or dry-run) of a scenario, persisted with a `run_id`. |

---

## 2. Overall Description

### 2.1 Product Perspective

A standalone ANY-LANGUAGE-PERFECT-FOR-THE-TOOL package exposing a CLI entry point named **`protoforge`**. State is persisted
in a local **SQLite** database and files under a `data/` tree. No network access is required for
the core ("minimal") path; network is used only when an LLM provider is configured or when real
scenario execution/capture is requested.

### 2.2 Pipeline (stages)

1. **Import** vulnerabilities (JSON/CSV) → normalized records in SQLite.
2. **Analyze** a vulnerability/description → structured `ThreatAnalysis` (LLM or offline rules).
3. **Generate** a controlled scenario → YAML (`Scenario`).
4. **Run** the scenario (dry-run by default) → optionally capture PCAP + persist a `RunRecord`;
   optionally validate real effect on the target.
5. **Build dataset** from flows (CSV) or PCAP → labeled CSV + metadata JSON.
6. **Train IDS** baseline (RandomForest + LogisticRegression) → best model + markdown report.
7. **Report**: assemble an end-to-end Markdown report from a `run_id`.

### 2.3 Actors

- **Researcher** — drives everything through the `protoforge` CLI.
- **API client** (optional) — calls the read-only FastAPI endpoints (`/health`, `/analyze`,
  `/generate-scenario`); the API never executes attacks.

### 2.4 Operating Environment

- **ANY-LANGUAGE-PERFECT-FOR-THE-TOOL 3.11+** (reference: 3.12), **no GPU / no CUDA**, ~2 GB RAM, ~500 MB disk.
- Linux, macOS, or Windows/WSL2.
- **Optional externals**: `tcpdump` (real capture), Docker (containerized targets/attacks),
  `cicflowmeter` CLI (PCAP→flows), an LLM API key (cloud analysis/synthesis), `scapy` (PCAP
  anomaly analysis).

### 2.5 Assumptions & Dependencies

- A sibling repository named `ataques/` may provide Docker lab targets
  (`iotedu-attack-xrce-dds-agent`, `iotedu-attack-zenoh-router`) and prepackaged attack containers
  (`iotedu-attack-*`). Scenarios may reference these images; the system does not build them.
- When an optional dependency is missing, the system **degrades gracefully** with an actionable
  message rather than crashing (RNF-02).

---

## 3. Functional Requirements

Requirements are grouped by capability. Each `RF-nn` is atomic and testable.

### 3.1 Vulnerability Ingestion

- **RF-01** The system SHALL import vulnerabilities from a local **`.json` or `.csv`** file.
  JSON MAY be a list, or an object containing a list under any of the keys
  `vulnerabilities` / `vulns` / `data` / `items`; a bare object is treated as a single record.
  CSV is read row-wise into records.
- **RF-02** The system SHALL **normalize** each raw record into the canonical `Vulnerability`
  model (see [A](#a-data-models)), tolerating common field aliases (e.g. `cve|cve_id|vuln_id → id`,
  `summary|desc → description`, `score|cvss_score|cvss_v3|base_score → cvss`, `cwe_id → cwe`,
  `published|publish_date|date → published_at`, `product|affected|vendor_product →
  affected_product`, `name → title`). Alias keys are matched case-insensitively with spaces
  normalized to `_`.
- **RF-03** `cvss` SHALL be parsed to float (tolerating strings/None/garbage → `None`) and
  **clamped to [0.0, 10.0]**.
- **RF-04** When `severity` is absent/empty it SHALL be **derived from cvss**:
  `≥9.0 critical`, `≥7.0 high`, `≥4.0 medium`, `≥0.1 low`, `>0 none`, `None → unknown`.
- **RF-05** A record with an empty `id` SHALL receive a deterministic placeholder id of the form
  `UNKNOWN-<n>`. Non-object records SHALL be skipped with a warning.
- **RF-06** Imported vulnerabilities SHALL be **upserted** (insert or replace by `id`) into SQLite.
- **RF-07** The system SHALL list imported vulnerabilities (`id | severity | cvss | title`).

### 3.2 Threat Analysis

- **RF-10** The system SHALL analyze either a **stored vulnerability** (by id) or **free text**,
  optionally with a **protocol hint**, and produce a structured `ThreatAnalysis` (see [A](#a-data-models)).
- **RF-11** Analysis SHALL support three provider modes selected by configuration/flags:
  `openrouter` (cloud, OpenAI-compatible), `local` (self-hosted OpenAI-compatible, e.g.
  Ollama/llama.cpp), and `offline` (rules only).
- **RF-12** If an LLM adapter is configured but the call fails, times out, or returns non-JSON /
  invalid output, the system SHALL **fall back to the rule-based analyzer** and log a warning
  (never crash).
- **RF-13** The rule-based analyzer SHALL detect the protocol and attack type by keyword
  heuristics (see [E](#e-threat-analysis-contract)) and emit `source="rules"`, `confidence=0.6`
  when an attack type matches, else `0.2` with `likely_attack_type="unknown"`.
- **RF-14** LLM responses SHALL be parsed by extracting the first JSON object from the text
  (tolerating markdown fences). The recorded `source` SHALL be the provider name.
- **RF-15** When analyzing a **stored** vulnerability, the produced analysis SHALL be **persisted**
  (one analysis per vuln id).
- **RF-16** LLM calls SHALL be **deterministic**: `temperature=0` and a fixed `seed` (both
  configurable). The model id and seed used SHALL be recordable for reproducibility.

### 3.3 Scenario Generation

- **RF-20** The system SHALL generate a `Scenario` (see [A](#a-data-models)) from a `ThreatAnalysis`
  and serialize it to **YAML**, given an output path, target (default `127.0.0.1`), capture
  interface (default `any`), and duration (default `30`).
- **RF-21** By default the scenario SHALL reference the **existing Docker attack container** for
  the (protocol, attack_type) pair when one exists (see table in [F](#f-scenario-generation-tables));
  with `--native`, it SHALL instead use the **native ANY-LANGUAGE-PERFECT-FOR-THE-TOOL attack module**.
- **RF-22** The scenario's **normal-traffic command** SHALL generate benign baseline traffic using
  the native flooding module in `--benign` mode.
- **RF-23** The system SHALL map each protocol to a default **(port, transport)**:
  `XRCE-DDS → 8888/udp`, `Zenoh → 7447/tcp`, `DDS → 7400/udp`; unknown → `0/udp`.
- **RF-24** The output YAML SHALL validate against the `Scenario` schema; invalid scenarios (on
  load) SHALL raise a **readable validation error** listing each offending field.

### 3.4 Scenario Execution & Capture

- **RF-25** The runner SHALL operate in **dry-run by default**: it prints, in order, the commands
  that *would* run (tcpdump capture, normal-traffic command, attack command) and **executes
  nothing**.
- **RF-26** Real execution SHALL require all of: `--no-dry-run`, `--execute`, and an explicit
  confirmation (`--yes` or an interactive confirm prompt). Missing confirmation SHALL raise an
  error and execute nothing.
- **RF-27** Before real execution, **every `--target` extracted from the scenario commands SHALL
  pass the safety guard** (RF-42); a non-lab target aborts the run.
- **RF-28** Real execution SHALL: create output dirs; require `tcpdump` on `PATH` (else error);
  start `tcpdump -i <iface> -w <pcap>` as a background process; wait ~1 s; run the normal-traffic
  command then the attack command (each with a timeout of `duration_seconds + 5`); then terminate
  capture cleanly (`terminate`, wait ≤5 s, else `kill`). A per-run **log file** SHALL be written.
- **RF-29** Every run (including dry-run) SHALL be **persisted** as a `RunRecord` with a generated
  `run_id` of the form `run-YYYYMMDD-HHMMSS-<6hex>`, alongside the serialized scenario YAML.
  Statuses: `dry-run` | `done` | `failed`.

### 3.5 Attack Synthesis (`forge-attack`)

- **RF-30** The system SHALL synthesize an attack from a CVE/free-text + its analysis. The LLM (or
  offline fallback) generates **only the body of** `mutate(baseline, seq, rng, urandom) -> bytes`;
  networking and the safety guard live in a fixed, trusted template.
- **RF-31** The generated mutator body SHALL be validated by an **AST whitelist sandbox** (see
  [I](#i-attack-synthesis--codegen-sandbox)) **before** it is written or executed. Rejected code
  SHALL cause fallback to a safe offline mutator (for LLM output) or a hard error (for the module
  writer).
- **RF-32** After validation, the mutator SHALL be **self-tested**: compiled and executed over a
  real protocol baseline for a few sequence numbers; each output MUST be non-empty `bytes` of
  length ≤ 65507. Failure rejects the candidate.
- **RF-33** The baseline used for grounding SHALL come from the **real protocol plugin**
  (`baseline_message`). If no plugin exists for the protocol, the attack is labeled
  **unvalidated / wire-level** and the baseline is empty (`b""`).
- **RF-34** On success the system SHALL write: a parameterized ANY-LANGUAGE-PERFECT-FOR-THE-TOOL attack module
  (`generated/attacks/<scenario_id>.py`), and — unless `--no-docker` — a Docker bundle
  (`docker/attacks/<scenario_id>/` with `Dockerfile`, `entrypoint.sh`, `docker-compose.yml`). With
  `--scenario-out` it SHALL also emit a `Scenario` YAML pointing at the generated module.
- **RF-35** Offline fallback mutators SHALL be provided per attack type (flooding/replay → identity;
  oversized → append large payload; malformed → corrupt header + append random; injection → append
  bytes; unknown → single-byte fuzz) and SHALL themselves pass the sandbox + self-test.

### 3.6 Native Attacks

- **RF-36** The system SHALL provide directly-runnable native attack modules:
  **flooding** (with `--benign` baseline mode), **replay** (from a PCAP), **fuzz** (strategies),
  **oversized** (max payload), **malformed** (corrupted headers).
- **RF-37** Every native attack SHALL enforce the safety guard (RF-42) on its `--target` before
  sending any traffic.

### 3.7 Protocol Plugin System

- **RF-38** Protocols SHALL be **pluggable** via a `ProtocolPlugin` base class exposing:
  `name`, `default_port`, `transport`, optional `target_image`, `install_hint`, `is_available()`,
  and the abstract methods `baseline_message(seq) -> bytes` and
  `health_probe(target, port) -> ProbeResult`, plus a default `capture_filter(port)` returning a
  BPF filter `"<transport> port <p>"`.
- **RF-39** A **registry** SHALL register/lookup plugins by a normalized name (lowercase, `_`/space
  → `-`, case-insensitive) and expose `register`, `get`, `available`, and idempotent
  `load_builtin()`. Built-in plugins: **XRCE-DDS, Zenoh, DDS**.
- **RF-40** Each built-in plugin's `baseline_message` SHALL emit a message with **real protocol
  framing** (e.g. XRCE `CREATE_CLIENT` with cookie `XRCE`, version, eProsima vendor id, session
  header; Zenoh frame; RTPS header). When the official protocol library is installed the plugin MAY
  provide a stronger session/probe; otherwise it degrades to a transport-level probe and reports
  itself accordingly.
- **RF-41** The system SHALL list registered protocols with their port/transport, whether the real
  lib is available, target image, and install hint if applicable.

### 3.8 Safety Guard

- **RF-42** The system SHALL refuse any attack `--target` that is **not** loopback, RFC1918
  private, or link-local — i.e. only `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, and link-local are allowed. Hostnames SHALL be resolved to an IP first; a
  non-resolving or public target raises `UnsafeTargetError` with an explanatory message.

### 3.9 Effect Validation Harness

- **RF-43** With validation enabled during a real run, the system SHALL: **probe the target before
  the attack** (via the protocol plugin's `health_probe`), run the attack + capture, **probe
  after**, analyze the PCAP, and emit an **effect verdict**: `valid` | `invalid` | `inconclusive`.
- **RF-44** The verdict rule SHALL be: responsive-before **and** not-responsive-after → `valid`;
  else PCAP anomalies present → `valid`; else responsive-before **and** responsive-after → `invalid`;
  otherwise → `inconclusive`.
- **RF-45** PCAP analysis SHALL count total packets, packets to/from the target, TCP **RST** flags,
  and **ICMP destination-unreachable (type 3)**; anomalies include RSTs, ICMP unreachable, and
  "target sent no response while receiving packets". If `scapy` or the PCAP is missing, it SHALL
  return empty stats with an explanatory note (no crash).
- **RF-46** The verdict, before/after responsiveness, and anomaly summary SHALL be stored on the
  `RunRecord` and surfaced to the user. (Only `valid` scenarios should be promoted to labeled
  attack samples — this is guidance for the researcher.)

### 3.10 Dataset Building

- **RF-47** The system SHALL build a labeled dataset from a **`.csv` of flows** or a
  **`.pcap`/`.pcapng`** (converted to flows via CICFlowMeter). The chosen **label** SHALL be added
  as a column (default column name `label`).
- **RF-48** If CICFlowMeter is unavailable, PCAP input SHALL fail with an actionable install/usage
  hint (not a silent failure). An empty flow set SHALL raise an error.
- **RF-49** The output SHALL be a CSV plus a sidecar **`<out>.meta.json`** (`DatasetMeta`) capturing
  name, source file, row count, label column, distinct labels, and UTC creation timestamp.
- **RF-50** The system SHALL support **merging** multiple labeled CSVs into one multi-class dataset
  (with its own metadata sidecar).

### 3.11 IDS Baseline Training

- **RF-51** The system SHALL train two baseline classifiers on a labeled CSV: **RandomForest**
  (`n_estimators=100`) and **LogisticRegression** (`max_iter=1000`, features standardized via
  `StandardScaler`). Both use `random_state=42`.
- **RF-52** Only **numeric** feature columns SHALL be used (label column excluded); `inf`/`-inf` →
  NaN → filled with `0.0`. Absence of the label column or of numeric features SHALL raise a clear
  error.
- **RF-53** Data SHALL be split with `test_size` (default `0.3`, `random_state=42`), stratified when
  the least-frequent class has ≥2 samples.
- **RF-54** For each model the system SHALL compute accuracy, precision, recall, F1 (binary averaging
  with the last-sorted label as positive when 2 classes, else macro), and a confusion matrix.
- **RF-55** The **best model by F1** SHALL be persisted as a joblib bundle
  `{model, features[, scaler]}` (scaler included only for LogisticRegression), named
  `<dataset_stem>_<BestModel>.joblib`, and a markdown report `<dataset_stem>_ids_report.md` (metrics
  table + confusion matrices) SHALL be written.

### 3.12 Reporting

- **RF-56** The system SHALL generate an **end-to-end Markdown report** from a `run_id`, joining the
  persisted run, its scenario, and (when available) the linked vulnerability, analysis, and dataset
  metadata. Output defaults to `reports/<run_id>.md`.

### 3.13 Optional HTTP API

- **RF-57** The system SHALL optionally expose a **read-only** FastAPI app with `GET /health`,
  `POST /analyze` (text + optional protocol → `ThreatAnalysis`), and `POST /generate-scenario`
  (→ scenario dict). The API SHALL **never execute attacks**. It requires the `api` extra.

---

## 4. Non-Functional Requirements

- **RNF-01 Offline-first / minimal path.** The full pipeline SHALL be runnable **offline, with no
  GPU, no network, no LLM key, no tcpdump/Docker**, using dry-run + rule-based analysis. This
  "minimal test" is the reference smoke test.
- **RNF-02 Graceful degradation.** Every optional dependency (LLM, tcpdump, Docker, CICFlowMeter,
  scapy, protocol libs) SHALL degrade with a clear, actionable message instead of crashing.
- **RNF-03 Reproducibility.** Dependencies SHALL be **pinned** (`requirements.txt` with exact
  versions). LLM determinism (`temperature=0` + `seed`) and the model/seed used SHALL be recorded on
  the run. The offline rule-based path is 100% deterministic and citable.
- **RNF-04 No GPU.** No CUDA/GPU dependency anywhere; scikit-learn on CPU trains the baseline in
  seconds.
- **RNF-05 Portability.** Runs on Linux, macOS, Windows/WSL2 with ANY-LANGUAGE-PERFECT-FOR-THE-TOOL 3.11+.
- **RNF-06 Security of generated code.** LLM-generated code SHALL be confined to a byte-payload
  transformation validated by an AST whitelist (no imports, no I/O, no `exec`/`eval`, no attribute
  access except whitelisted `rng` methods, bounded constants, mandatory `return`). Networking and
  the target guard are never AI-generated.
- **RNF-07 Safety by default.** Destructive actions are opt-in and gated; dry-run is the default;
  targets are restricted to lab ranges.
- **RNF-08 Testability.** A pytest suite SHALL cover the sandbox, normalizer, scenario validation,
  dataset builder, protocol registry, PCAP analysis, and validation harness. Reference suite:
  **50 passing** tests.
- **RNF-09 Packaging.** Distributed as an installable package exposing the `protoforge` console
  script; optional extras `api`, `traffic`, `zenoh`, `dds`, `dev`.
- **RNF-10 Container hygiene.** A `ANY-LANGUAGE-PERFECT-FOR-THE-TOOL:3.11-slim` (no GPU) Docker image with a single install
  layer; `docker-compose.yml` without the obsolete `version:` field and without personal absolute
  paths (relative volumes `./data`, `./scenarios`, `./reports`); `.dockerignore` excludes
  `.venv/`, `.git/`, run artifacts. The default `CMD` runs the minimal test.
- **RNF-11 Logging.** Structured, level-configurable logging (default `INFO`) across modules.

---

# Part II — Implementation Appendix

> This appendix gives the concrete contracts. All models are **Pydantic v2** `BaseModel`s unless
> noted. Defaults shown are normative.

## A. Data Models

### `AttackType` (str enum)
`flooding`, `replay`, `malformed_message`, `oversized_payload`, `injection_simulated`, `normal`,
`unknown`.

### `Vulnerability`
| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | str | — | required |
| `title` | str | `""` | |
| `description` | str | `""` | |
| `source` | str | `"manual"` | |
| `cvss` | float \| None | `None` | **validator: clamp to [0,10]** |
| `severity` | str | `"unknown"` | |
| `cwe` | str | `""` | |
| `published_at` | str | `""` | |
| `affected_product` | str | `""` | |

### `ThreatAnalysis`
| Field | Type | Default | Notes |
|---|---|---|---|
| `protocol` | str | `"unknown"` | |
| `likely_attack_type` | `AttackType` | `unknown` | |
| `preconditions` | str | `""` | |
| `expected_network_behavior` | str | `""` | |
| `dataset_label` | str | `"unknown"` | e.g. `xrce_dds_flooding` |
| `confidence` | float | `0.0` | **0.0 ≤ x ≤ 1.0** |
| `safety_notes` | str | `""` | |
| `source` | str | `"rules"` | `rules` \| `openrouter` \| `local` |

### `Scenario` (serialized as YAML)
| Field | Type | Default | Notes |
|---|---|---|---|
| `scenario_id` | str | — | required |
| `protocol` | str | — | required |
| `attack_type` | `AttackType` | — | required |
| `duration_seconds` | int | `30` | **0 < x ≤ 3600** |
| `normal_traffic_command` | str | `""` | |
| `attack_command` | str | `""` | |
| `capture_interface` | str | `"any"` | |
| `output_pcap` | str | — | required |
| `label` | str | — | required |
| `notes` | str | `""` | |

YAML (de)serialization: dump with `sort_keys=False`, `allow_unicode=True`; load with a YAML safe
loader, requiring a top-level mapping; validation errors are re-raised as a readable
`ScenarioValidationError` (`"Cenario invalido: field: msg; ..."`).

### `DatasetMeta`
`name`, `source_file`, `rows:int`, `label_column`, `labels:list[str]`, `created_at` (UTC ISO),
`notes`.

### `RunRecord`
`run_id`, `scenario_id`, `vuln_id=""`, `started_at`, `status="created"`
(`created|dry-run|running|done|failed`), `log_path=""`, `pcap_path=""`,
`effect_verdict="not_validated"` (`valid|invalid|inconclusive|not_validated`),
`responsive_before=""`/`responsive_after=""` (`yes|no|unknown`), `anomalies=""`,
`llm_model=""`, `llm_seed=""`.

### `ProbeResult`
`responsive:bool=False`, `detail:str=""`, `latency_ms:float|None=None`,
`source:str="probe"` (`probe|plugin|tcp|udp`).

### `EffectReport`
`verdict:str="inconclusive"` (`valid|invalid|inconclusive`), `responsive_before:bool|None`,
`responsive_after:bool|None`, `packets_out:int=0`, `packets_in:int=0`,
`anomalies:list[str]`, `notes:str=""`.

## B. Configuration

Settings load from environment / `.env` (pydantic-settings). **Prefix `VULNFORGE_`** for all keys
**except** `OPENROUTER_API_KEY`, which is read without prefix. `extra="ignore"`.

| Setting | Env | Default |
|---|---|---|
| `llm_provider` | `VULNFORGE_LLM_PROVIDER` | `openrouter` (`openrouter\|local\|offline`) |
| `llm_model` | `VULNFORGE_LLM_MODEL` | `anthropic/claude-sonnet-4` |
| `llm_base_url` | `VULNFORGE_LLM_BASE_URL` | `https://openrouter.ai/api/v1` |
| `openrouter_api_key` | `OPENROUTER_API_KEY` | `""` |
| `llm_temperature` | `VULNFORGE_LLM_TEMPERATURE` | `0.0` |
| `llm_seed` | `VULNFORGE_LLM_SEED` | `1337` |
| `db_path` | `VULNFORGE_DB_PATH` | `data/vulnforge.db` |
| `data_dir` | `VULNFORGE_DATA_DIR` | `data` |
| `log_level` | `VULNFORGE_LOG_LEVEL` | `INFO` |

Derived paths: `datasets_dir = data/datasets`, `models_dir = data/models`, `runs_dir = data/runs`.
Settings SHOULD be a process singleton. An LLM adapter is built only when a provider is configured
and (for cloud) a key is present; otherwise the analyzer/synthesizer use the offline path.

## C. Persistence (SQLite)

Open a connection that ensures the parent dir exists, sets `row_factory = Row`, and initializes the
schema (idempotent, with lightweight `ALTER TABLE` migrations for new `runs` columns). Tables:

- **`vulnerabilities`** — columns mirror `Vulnerability` (`id` PRIMARY KEY).
- **`analyses`** — `vuln_id` PK + the `ThreatAnalysis` fields + `created_at`.
- **`runs`** — `run_id` PK, `scenario_id`, `vuln_id`, `started_at`, `status`, `log_path`,
  `pcap_path`, `scenario_yaml`, and the Fase-2 columns `effect_verdict` (default
  `'not_validated'`), `responsive_before`, `responsive_after`, `anomalies`, `llm_model`,
  `llm_seed`.

Repository functions: `upsert_vuln`, `get_vuln`, `list_vulns`, `save_analysis`, `get_analysis`,
`save_run(record, scenario_yaml)`, `get_run`.

## D. CLI Contract (`protoforge`)

Built with Typer; `no_args_is_help=True`; the root callback initializes logging from settings.
Common flags `--provider/--model` override settings at runtime.

| Command | Key options (defaults) | Behavior / stdout |
|---|---|---|
| `import-vulns` | `--file` (req) | Import + normalize + upsert. Prints count and one line per vuln. |
| `analyze` | `--vuln-id` \| `--text`, `--protocol`, `--provider`, `--model` | Analyze; if `--vuln-id`, persist analysis. Prints `ThreatAnalysis` as indented JSON. Requires one of vuln-id/text. |
| `generate-scenario` | `--vuln-id`\|`--text`, `--protocol`, `--target 127.0.0.1`, `--interface any`, `--duration 30`, `--native`, `--out` (req) | Reuse stored analysis or analyze; write YAML; print path. |
| `run-scenario` | `--file` (req), `--dry-run/--no-dry-run` (default dry-run), `--execute`, `--yes`, `--validate`, `--vuln-id` | Dry-run prints planned commands; real run gated by `--no-dry-run --execute` + confirm. Prints `run_id` + status (+ pcap/log/verdict when executed). |
| `build-dataset` | `--flows` (req), `--label` (req), `--out` (req), `--label-column label` | Build labeled CSV + meta. Prints rows + labels. |
| `train-ids` | `--dataset` (req), `--label-column label`, `--test-size 0.3` | Train RF+LogReg; print result dict JSON. |
| `report` | `--run-id` (req), `--out` | Build end-to-end MD report; print path. |
| `gen-attack-docker` | `--type all\|flooding\|replay\|fuzz\|oversized\|malformed`, `--out docker/attacks` | Emit Dockerfile(s) for native attacks. |
| `forge-attack` | `--vuln-id`\|`--text`, `--protocol`, `--target 127.0.0.1`, `--out-code generated/attacks`, `--out-docker docker/attacks`, `--no-docker`, `--scenario-out`, `--provider`, `--model` | Synthesize mutator → validate+self-test → write module (+Docker bundle) (+scenario YAML). |
| `protocols` | — | List registered plugins, availability, target image, install hint. |
| `list-vulns` | — | List imported vulns. |

Errors from safety/validation/missing-deps SHALL surface as clear CLI errors (Typer
`BadParameter`), not tracebacks.

## E. Threat Analysis Contract

**Protocol keyword hints** (canonical → terms; matched on lowercased text):
- `XRCE-DDS`: `xrce`, `micro-xrce`, `microxrce`, `micro xrce`, `uxr`, `agent`
- `Zenoh`: `zenoh`
- `DDS`: `dds`, `rtps`, `fast dds`, `fastdds`, `cyclonedds`, `data distribution`

If a `--protocol` hint is given, canonicalize by matching against the above (with `_`→`-`), else use
the hint verbatim.

**Attack keyword hints** (evaluated in this priority order; first match wins, `confidence=0.6`):
1. `oversized_payload`: `oversized`, `large payload`, `max frame`, `65535`, `buffer overflow`, `oversize`
2. `malformed_message`: `malformed`, `fuzz`, `parser`, `invalid`, `corrupt`, `crafted`, `fragment`
3. `replay`: `replay`, `retransmit`, `captured message`, `session hijack`, `spoof`
4. `injection_simulated`: `injection`, `inject`, `poison`, `tamper`
5. `flooding`: `flood`, `dos`, `denial of service`, `exhaust`, `amplification`, `keepalive`, `udp flood`

No match → `unknown`, `confidence=0.2`. `dataset_label = "<proto_slug>_<attack.value>"` where
`proto_slug` lowercases the protocol and replaces `-`/space with `_`.

**LLM flow:** build system+user prompts, call adapter, extract first JSON object, coerce into
`ThreatAnalysis` with `source=<provider>`; on any error/invalid → rule-based fallback.

## F. Scenario Generation Tables

**Protocol → (port, transport):** `XRCE-DDS → (8888, udp)`, `Zenoh → (7447, tcp)`,
`DDS → (7400, udp)`, otherwise `(0, udp)`.

**attack_type → existing container** (reuse of the `ataques/` repo):

| attack_type | XRCE-DDS | Zenoh |
|---|---|---|
| flooding | `iotedu-attack-xrce-dds-udp-dos` | `iotedu-attack-zenoh-pico-keepalive-flood` |
| malformed_message | `iotedu-attack-xrce-dds-malformed-inject` | `iotedu-attack-zenoh-pico-proto-fuzzer` |
| replay | `iotedu-attack-xrce-dds-session-hijack` | `iotedu-attack-zenoh-pico-timestamp-mess` |
| oversized_payload | `iotedu-attack-xrce-dds-fragment-abuse` | `iotedu-attack-zenoh-pico-memory-exhaustion` |
| injection_simulated | `iotedu-attack-xrce-dds-discovery-poison` | — |

**attack_type → native module:** flooding→`flooding`, replay→`replay`,
malformed_message→`malformed`, oversized_payload→`oversized`, injection_simulated→`malformed`.

**Normal-traffic command template:**
`ANY-LANGUAGE-PERFECT-FOR-THE-TOOL -m vulnforge.traffic.attacks.flooding --target <t> --port <p> --transport <tr> --rate 5 --duration 20 --benign`

`scenario_id`/labels are slugified: lowercase, `-`/space → `_`.

## G. Scenario Runner & Effect Validation

- `run_id = "run-" + UTC "%Y%m%d-%H%M%S" + "-" + uuid4().hex[:6]`.
- **Dry-run** prints a header (scenario, run_id, pcap, interface, duration, label) then each planned
  command prefixed with `$`. Command order: `tcpdump -i <iface> -w <pcap>`, then normal-traffic,
  then attack (omitting empty commands). Returns a `RunRecord(status="dry-run")`.
- **Real run** (see RF-27/28): safety-check all targets; require tcpdump; probe-before (if
  `--validate` and plugin exists); start capture; sleep 1 s; run normal then attack commands
  (subprocess with timeout `duration+5`, capture stdout/stderr into the log); on any error set
  `status="failed"` and continue to teardown; stop capture; probe-after; build `EffectReport`;
  persist `RunRecord` (`status` `done`/`failed`; `llm_model` = model or `"offline"`; `llm_seed`).
- **Port extraction:** read `--port` from the attack (then normal) command; else plugin default.
- **Verdict logic** (`decide_verdict(before, after, stats)`): as in RF-44.
- **PCAP stats** (`analyze_pcap`): counts + TCP RST (`flags & 0x04`) + ICMP type 3; anomalies as in
  RF-45; `scapy` optional.

## H. Protocol Plugin System

`ProtocolPlugin` (ABC): class attrs `name`, `default_port`, `transport` (`udp|tcp`),
`target_image:str|None`, `install_hint:str`; methods `is_available()->bool` (default `True`),
abstract `baseline_message(seq)->bytes`, abstract `health_probe(target, port=None)->ProbeResult`,
`capture_filter(port=None)->str` (default `"<transport> port <port|default>"`), and `require()`
(raise `ProtocolDependencyError` with `install_hint` if unavailable).

A neutral `identity_mutator(baseline, seq, rng) -> baseline` is provided for benign flooding.

**Registry:** normalized keys; `register/get/available/load_builtin`. Built-ins:
- **XRCE-DDS** — UDP 8888, `target_image="iotedu-attack-xrce-dds-agent:latest"`. Baseline =
  a valid `CREATE_CLIENT` (cookie `XRCE`=`0x58 0x52 0x43 0x45`, version `0x01 0x00`, eProsima vendor
  `0x01 0x0F`, session header with `session_id≥0x80`, little-endian seq). Uses stdlib only.
- **Zenoh** — TCP 7447; frame-based baseline; stronger session if `eclipse-zenoh` installed.
- **DDS** — UDP 7400; RTPS-framed baseline; stronger session if `cyclonedds` installed.

## I. Attack Synthesis & Codegen Sandbox

**Synthesis (`exploit_synth`):** resolve `(port, transport)` from the plugin (or protocol defaults
`XRCE-DDS 8888/udp`, `Zenoh 7447/tcp`, `DDS 7400/udp`, else `9999/udp`); get the real baseline from
the plugin. If an LLM adapter exists, prompt it for a JSON
`{strategy, transport, port, rate, duration, rationale, mutator_code}`; accept **only if** the
`mutator_code` passes the sandbox **and** self-test over the baseline; otherwise use the offline
mutator for the inferred attack type (which is itself sandbox+self-tested).

**Offline mutator bodies** (by `AttackType`):
- flooding / replay → `return baseline`
- oversized_payload → `return baseline + b'\xff' * 60000`
- malformed_message → xor first byte, randomize second, append `urandom(8)`
- injection_simulated → `return baseline + b'A' * rng.randrange(16, 256)`
- unknown → flip one random byte

**Sandbox (`codegen`) — AST whitelist** applied to the function body:
- The body is wrapped as a function with the appropriate args and parsed. It MUST contain a
  `return <value>`.
- **Allowed builtins:** `bytes, bytearray, int, float, bool, len, range, min, max, abs, list,
  tuple, sum, ord, chr, bin, hex, reversed, enumerate`.
- **Allowed `rng` methods (only):** `randrange, randint, random, getrandbits, choice, randbytes`.
  No other attribute access is permitted.
- **Injected names:** `build_payload(seq, rng, urandom)` or `mutate(baseline, seq, rng, urandom)`.
- **Forbidden AST nodes:** `Import, ImportFrom, While, With, AsyncWith, Try, Raise, Global,
  Nonlocal, ClassDef, FunctionDef, AsyncFunctionDef, Lambda, Await, Yield, YieldFrom, Delete,
  Starred`.
- **Forbidden:** `**` (Pow) operator; calls to non-whitelisted names or dynamic call targets;
  loads of undefined names; integer constants with `abs(value) > 1_000_000` (`MAX_CONST_INT`).
- **Compilation** uses `__builtins__` restricted to the allowed builtins only.
- **Self-test:** run the compiled function for ~6 sequence numbers; each result MUST be
  `bytes`/`bytearray`, non-empty, length ≤ **65507**. Payloads are truncated to 65507 at send time.
- Violations raise `CodeValidationError`.

**Generated module template** imports only from `vulnforge.traffic.attacks.common`
(`run_and_report`, `send_loop`, `synth_parser`) and (for mutator modules) `vulnforge.protocols
.registry`; it wires a seeded `random.Random`, builds payloads via the validated function, sends via
`send_loop(transport, target, port, duration, rate, factory)`, and reports. Default seed `1337`.

## J. Dataset Building & IDS Training

**Builder:** `.csv` loaded directly; `.pcap/.pcapng` converted via CICFlowMeter CLI
(`cicflowmeter -f <pcap> -c <tmp.csv>`) — missing tool → `RuntimeError` with install hint. Add the
label column, write CSV, write `<out>.meta.json`. `merge_datasets` concatenates CSVs (label column =
`label` if present else last column).

**Trainer:** as RF-51..RF-55. `result_to_dict` returns
`{dataset, rows, best_model, model_path, report_path, metrics:[{model,accuracy,precision,recall,f1}]}`.
Report is Markdown: header (dataset, rows, classes, feature list, best model), a metrics table, and
one confusion matrix per model.

## K. Reporting

`build_report(run_id, out_path=None)` loads the run (+ scenario YAML, and linked vuln/analysis when
present, plus dataset meta discovered next to the PCAP if any) and renders a single Markdown report;
default path `reports/<run_id>.md`.

## L. Optional HTTP API

FastAPI app titled "VulnForge AI". Importing it without FastAPI installed raises a `RuntimeError`
pointing at the `api` extra. Endpoints: `GET /health → {"status":"ok"}`,
`POST /analyze {text, protocol?} → ThreatAnalysis`,
`POST /generate-scenario {text, protocol?} → scenario dict`. No execution endpoints.

## M. Project Layout & Dependencies

```
src/vulnforge/
├── __init__.py, cli.py, config.py, db.py, logging_setup.py, models.py, api.py
├── vulnerability/   # normalizer, repository (SQLite), collector
├── llm/             # adapter (OpenRouter/local), rules, analyzer, exploit_synth, prompts
├── protocols/       # base, registry, xrce_dds, zenoh, dds
├── scenarios/       # schema (Pydantic), generator, examples/
├── traffic/         # safety, runner, codegen (sandbox), docker_gen, attacks/{flooding,replay,
│                    #   fuzz,oversized,malformed,common}
├── validation/      # harness (verdict), pcap_analysis
├── dataset/         # builder, cicflowmeter
├── ids/             # trainer (RF + LogReg, metrics, joblib, md)
└── reports/         # generator (Markdown end-to-end)

scripts/             # setup.sh (env) + run-minimal.sh (minimal offline test)
scenarios/examples/  # sample scenario YAMLs
Dockerfile, docker-compose.yml, .dockerignore
requirements.txt     # PINNED versions (reproducibility)
pyproject.toml       # console script `protoforge`
tests/               # pytest suite (reference: 50 passing)
```

**Runtime deps:** `typer>=0.12`, `pydantic>=2.6`, `pydantic-settings>=2.2`, `pandas>=2.1`,
`scikit-learn>=1.4`, `joblib>=1.3`, `requests>=2.31`, `PyYAML>=6.0`.
**Optional extras:** `api` (`fastapi`,`uvicorn`), `traffic` (`scapy`), `zenoh` (`eclipse-zenoh`),
`dds` (`cyclonedds`), `dev` (`pytest`).
**Entry point:** `protoforge = "vulnforge.cli:app"`. **Requires ANY-LANGUAGE-PERFECT-FOR-THE-TOOL ≥3.11.**

## N. Acceptance Criteria

The implementation is accepted when:

1. **Minimal offline pipeline** (no key/network/tcpdump/Docker) runs end-to-end via
   `scripts/run-minimal.sh`: import → analyze (rule-based) → generate scenario → run-scenario
   dry-run → build-dataset → train-ids → report, finishing successfully and producing a scenario
   YAML, labeled dataset, IDS model + report, and a Markdown run report.
2. **Rule-based analysis** of an XRCE-DDS resource-exhaustion CVE yields
   `likely_attack_type=flooding`, `dataset_label=xrce_dds_flooding`, `source=rules`,
   `confidence=0.6`.
3. **Safety guard** rejects a public IP/host (`UnsafeTargetError`) and accepts loopback/private.
4. **Sandbox** rejects mutator code containing `import`, `open`, `eval`, attribute access other than
   whitelisted `rng.*`, `**`, `while`, or an integer constant > 1,000,000; and accepts a valid
   body that returns bounded bytes.
5. **LLM absence** (no key) transparently falls back to rule-based analysis / offline synthesis.
6. **IDS training** on the sample linearly-separable dataset (120 rows, `test_size=0.3`) selects
   RandomForest and reports F1 = 1.00 for both baselines (pipeline validation, not a detection
   benchmark), writing the joblib bundle and markdown report.
7. **Scenario round-trip**: a generated YAML re-loads and validates; malformed YAML yields a
   readable field-level error.
8. **`pytest -q`** passes (reference: 50 passing) covering sandbox, normalizer, scenario validation,
   dataset builder, protocol registry, PCAP analysis, and validation harness.
9. **Docker**: `docker compose up --build` runs the minimal test and writes artifacts to
   `./data` / `./reports` via relative volumes.
