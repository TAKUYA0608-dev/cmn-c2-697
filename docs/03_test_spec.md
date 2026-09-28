# Test Specification — CMN-C2-697

## Test Strategy
- Coverage target: **80%+** (achieved **95%**, `--cov=src`)
- Test types: Unit (pre/post + inner nodes + services) / Unit (Cat 2 graph wiring + real invoke) / Integration / Proof-of-Boundary
- Determinism: **no LLM** — namespace routing, BM25-lite reference retrieval, reference-to-context mapping,
  least-privilege IAM composition, and deliverable synthesis are pure tokenization + keyed KB composition
  (reproducible, auditable, grounded in a cited AWS-official reference). No model is declared in
  `config/agent.yaml` and no LLM dependency in `pyproject.toml`.

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State contract: flat TypedDict | `State(AgentState)`, NotRequired primitives + JSON strings; no PII/credential fields | ✅ PASS |
| TC-02 | S-2 rejection is degraded, never `status=ERROR` | `_extra_security_gate_input` sets `error_code` (`INJECTION_REJECTED`/`INPUT_TOO_LONG`) and returns `dict(state)`; never raises, never sets `status=ERROR` | ✅ PASS |
| TC-03 | No JWT/Credential in `src/` | `gate-credential-scan`: 0 violations | ✅ PASS |
| TC-04 | InvocationContext read-only | never stored in State | ✅ PASS |
| TC-05 | S-4: no duplicate lifecycle events | only domain events emitted (never node_start/complete) | ✅ PASS |
| TC-06 | S-2 `_security_gate_input()` not overridden | `@final`; only `_extra_*` extended | ✅ (real SDK on CI; local-stub env-diff) |
| TC-07 | S-3 `_security_gate_output()` not overridden | `@final`; may raise via `_extra_*` | ✅ (real SDK on CI; local-stub env-diff) |
| TC-08 | `required_trust_level` explicit on every FunctionNode | `VERIFIED_EXTERNAL` (gate-trust-level-check) | ✅ PASS |
| TC-09 | Cat consistency | Template ID / config / README all Cat 2 (gate-cat-consistency) | ✅ PASS |
| TC-10 | Exact dependency pins | `==` in all sections incl. `[build-system]` setuptools==68.0.0 (gate-dep-pinning) | ✅ PASS |
| TC-11 | S-4: ≥1 domain `emit_trace_event()` per `execute()` | emitted on every path (incl. skip / safe branches) | ✅ PASS |
| TC-12 | Degraded path never `status=ERROR` | injection / oversize / empty / 0-reference → `SUCCESS.value + error_code`; `post_process` still runs | ✅ PASS |
| TC-13 | Input hygiene: PII / secrets never persist in State | credential / My-Number / email / phone redacted from every supplied free-text field (query + deployment descriptors); deployment ids tokenized | ✅ PASS |
| TC-14 | Real `Graph().invoke()` degraded path | injection & oversize → SUCCESS + out-of-scope, `PostProcessNode` in node_history, error_code in terminal S-4 audit, rejected body absent, DRAFT disclaimer present | ✅ PASS |
| TC-15 | S-3 fail-closed citation completeness | grounded advisory with no reference citation, or any supplied deployment with unresolved provenance → `needs_review` degrade (SUCCESS + `CITATION_INCOMPLETE`), deliverable body withheld, disclaimer + audit still run; verified via real `Graph().invoke()` | ✅ PASS |
| TC-16 | Provenance allowlist + output redaction | unverifiable / forged deployment `source` dropped, never in `formatted_output`; query PII (email/phone/credential) redacted in a grounded output | ✅ PASS |
| TC-17 | Opaque-id boundary — privacy tokenize (deployment_id) | `deployment_id`/`agent_id`/`id` → `dep:<sha8>` UNCONDITIONALLY (a no-space name `Alice`/`prod-agent`/`TaroYamada` is tokenized, not passed through); deterministic; surrogate namespace idempotent; verified via real `Graph().invoke()` | ✅ PASS |
| TC-18 | Provenance validation (separate from privacy) | a caller `source` is a grounded deployment citation ONLY if it names an authorized deployment/IaC system of record; unverifiable source (deployment name / `unknown` / fabricated) **and a forged surrogate (`src:1a2b3c4d` / `dep:deadbeef`)** → `None` → `needs_review` (CITATION_INCOMPLETE), never a citation; authorized `cloudformation:…` / `terraform:…` → privacy-tokenized `src:<sha8>`; verified via real `Graph().invoke()` | ✅ PASS |
| TC-19 | IAM least-privilege anti-hallucination | every IAM template action is drawn only from a cited KB reference (`_citation` = `stat:<sha8>`); no `Resource: "*"` (placeholder ARN); verified via real `Graph().invoke()` | ✅ PASS |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Expected Result | Result |
|-------|----------|----------------|--------|
| PB-2/5 | Post-invoke State is primitives only; no credential fields | AST scan: 0 violations | ✅ PASS |
| PB-4 | Import isolation — no Level 0 (`agenticstar`) imports | AST scan: 0 violations | ✅ PASS |
| PB-6 | Invoke order S-1 → S-4(start) → S-2 → execute → S-3 → S-4(complete) | Order verified | ✅ (real SDK on CI; local-stub env-diff) |
| PB-7 | HITL interrupt propagation | conditional — SKIPPED (`hitl.enabled` not set for this template) | ✅ (n/a, skip) |
| S-0 | Cat 2 `GraphNode`-in-main wraps inner `BaseGraph` (cached `get_subgraph`) | gate-composition passes | ✅ PASS |

## Business Logic Tests

| BL-ID | Test | Input | Expected Result | Result |
|-------|------|-------|----------------|--------|
| BL-01 | Namespace routing | query "deploy … Bedrock AgentCore … least-privilege IAM …" | `{deploy, iam, bedrock}`; token-based | ✅ PASS |
| BL-02 | BM25-lite retrieval | deployment query | ≥1 relevant reference (agentcore-runtime-deploy + iam…); every reference KB-cited `stat:<sha8>`; descending score, stable tie-break | ✅ PASS |
| BL-03 | Out-of-domain retrieval | "how do I bake a cake" | `[]` → out-of-scope safe answer | ✅ PASS |
| BL-04 | Reference → context mapping | reference + deployment_target + jurisdictions | applicability annotation; general-guidance fallback | ✅ PASS |
| BL-05 | Least-privilege IAM template | retrieved references with iam_actions | grounded `_citation` per statement; no `Resource:"*"`; None when no actions | ✅ PASS |
| BL-06 | Code-example collection | references with code_example | cited grounded snippets collected | ✅ PASS |
| BL-07 | Deployment audit trail | resolved vs unresolved provenance | `documented`+citation vs `unverified`+`None`; malformed rows dropped | ✅ PASS |
| BL-08 | Grounded advisory (no deployments) | deployment question only | `deployment_advisory`, citations + IAM template present, `citation_complete=True` | ✅ PASS |
| BL-09 | Grounded advisory (authorized deployment) | deployment with `cloudformation:…` source | grounded; deployment `provenance_status=documented`, id `dep:<sha8>` | ✅ PASS |
| BL-10 | FISC residency lens | query with FISC/residency/JP | `fisc_residency` section with a grounded citation | ✅ PASS |
| BL-11 | Empty input degrades | "   " | `SUCCESS.value + INPUT_REJECTED`, still audits | ✅ PASS |
| BL-12 | Mandatory DRAFT disclaimer | any output | S-3 gate blocks output missing 参考/DRAFT | ✅ PASS |
| BL-13 | S-3 fail-closed (deployment provenance) | supplied deployment with unresolved/forged source | grounded advisory degrades to `needs_review`, deliverable withheld, `CITATION_INCOMPLETE` | ✅ PASS |
| BL-14 | S-3 fail-closed (no reference citation) | grounded report with empty citations | `needs_review` (CITATION_INCOMPLETE) | ✅ PASS |
| BL-15 | Privacy tokenize (deployment_id) | `deployment_id` = `Taro Yamada 090-…` **or no-space name** | tokenized to `dep:<sha8>`; original absent from output | ✅ PASS |
| BL-16 | Provenance safety / no leak | unverifiable `source` (name+phone) | dropped/redacted — not in `formatted_output` | ✅ PASS |
| BL-17 | Provenance validation (fail-closed) | `source` = deployment name / `unknown` / fabricated | no citation → `needs_review`; source not in output | ✅ PASS |
| BL-18 | Forged-surrogate defence | `source` = `src:1a2b3c4d` / `dep:deadbeef` | unauthorized namespace → dropped → `needs_review`, never a citation; error_code in terminal S-4 audit | ✅ PASS |
| BL-19 | Authorized provenance accepted | `source` = `cloudformation:…` / `terraform:…` | grounded; citation = tokenized `src:<sha8>`; raw not in output | ✅ PASS |
| BL-20 | Query PII redaction in grounded output | query with email/phone/credential | redacted from `formatted_output` (S-3 defense-in-depth) | ✅ PASS |

## Test Execution Summary
- Total: 84 (unit-nodes 47 + unit-graph 31 + integration 6) + active PB (import_isolation, state_safety, S-0 via graph wiring)
- Pass: 83 (core) · Skip: server-import (local stub env-diff) + PB-7 ×2 (conditional, HITL off)
- env-diff: `test_pb_invoke_order` + `test_framework_compliance_tc06_tc07` (TC-06/07/PB-6) assert against the
  real SDK on CI (the local SDK stub lacks the `emit_trace_event` surface / `@final` gate enforcement); all pass on CI
- Coverage: **95%** (`--cov=src`)
