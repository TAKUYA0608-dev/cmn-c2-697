# Template Design Specification — CMN-C2-697

Enterprise AWS AgentCore Deployment Q&A — Cat 2, GraphNode-in-main.

## Position in AgentCore Architecture

- **Agent Class**: `AwsAgentCoreDeploymentQaAgent` (module-level alias of `Graph`)
- **L1 Base**: AgentBaseGraph (L1 direct — Cat 2 GraphNode-in-main; **not** AutonomousBaseGraph)
- **Category**: Cat 2 — orchestrates a fixed multi-step deployment-advisory workflow to produce one
  job-to-be-done deliverable (a cited AWS-deployment answer + a least-privilege IAM policy template + a FISC
  cloud-residency lens), cited to AWS-official references. `VectorRAGAgent` is a pattern reference only
  (L2 deprecation 2026-05-18).
- **Three-Layer Separation**:
  - State: flat TypedDict composition (no Pydantic — msgpack incompatible); complex fields are JSON strings (ADR-005)
  - Node: L1 inheritance (Template Method: `execute(self, state: dict) -> dict` override only — no `config` param)
  - Graph: composition (`register_nodes()` for node substitution; domain complexity behind a `GraphNode`)

## Architecture Overview

### Node Configuration (outer 5-slot backbone)

| Node | Responsibility | Input State | Output State | Inherits/Overrides |
|------|---------------|-------------|--------------|-------------------|
| initialize | schema/session/trust setup | user_input | caller_trust_level, session_id | InitializeNode (default) |
| pre_process | `QueryNormalize` — S-1/S-2 validation, NFKC, size cap, injection→degraded, field-level input hygiene (credential/My-Number/email/phone redaction on **every** supplied free-text field — query + deployment descriptors; **deployment `deployment_id`/`agent_id` UNCONDITIONALLY privacy-tokenized to `dep:<sha8>` — no syntactic passthrough, a bare name is opaque like any value**; **provenance `source` resolved to a citation ONLY if it names an authorized deployment/IaC system of record (privacy-tokenized `src:<sha8>`), else dropped to `None`** — S-3 then blocks) | user_input | validated_input, input_format, enriched_context, (error_code) | PreProcessNode (FunctionNode) |
| main | `DeploymentAdvisoryWorkflowGraphNode` — wraps inner `DeploymentAdvisoryWorkflow` (composition criterion #9) | validated_input | result, retrieval_hit_count, (error_code), status | GraphNode (subgraph) |
| post_process | `ResponseValidate` — S-3 output gate: **fail-closed citation completeness** (a grounded advisory with no reference citation, or with any supplied deployment whose provenance did not resolve → `needs_review` degrade, deliverable body withheld, `error_code=CITATION_INCOMPLETE`) + credential/My-Number/email/phone re-redaction + DRAFT "verify before applying" disclaimer, S-4 audit | result | formatted_output, disclaimer, audit_logged, (error_code) | PostProcessNode (FunctionNode) |
| finalize | build response envelope | formatted_output | output, status | FinalizeNode (default) |

### Inner workflow (`src/graph/domain_workflow_graph.py` — BaseGraph, linear + per-node skip guard)

```
START → ingest_scope → knowledge_retrieve → interpret_analyze → answer_synthesize → END
```

Faithful to the SoT §4 workflow (DocNamespaceRoute → HybridRetrieve → ResponseGenerate → CodeExampleExtract),
realized as a 4-node inner deployment-advisory workflow.

| Inner Node | Responsibility | Skip guard |
|------|---------------|-----------|
| ingest_scope | Route the normalized query to KB namespace(s) (deploy / iam / bedrock / fisc) for scoped retrieval, and normalize the deployment context. Deterministic keyword routing | no-op `return {}` (after `.skip` emit) on `error_code` (pre-stage rejection) |
| knowledge_retrieve | Deterministic BM25-lite retrieval over the seeded AWS deployment/ops reference KB (AWS Agent Toolkit / Amazon Bedrock AgentCore / Bedrock / IAM / FISC — all AWS-official sources), scoped by routed namespaces. Set `retrieval_hit_count`. **0 references matched (rejected input or out-of-domain query) → `error_code=NO_REFERENCE` → out-of-scope safe answer** | skip → `retrieval_hit_count=0`, propagate `error_code` (after `.skip` emit) |
| interpret_analyze | Deterministic mapping of each retrieved reference to the caller deployment context (deployment_target / jurisdictions) → per-reference applicability annotation | no-op `return {}` (after `.skip` emit) on `error_code` / `retrieval_hit_count == 0` |
| answer_synthesize | Compose the deliverable: cited answer sections (one per retrieved reference), a **least-privilege IAM policy template composed only from KB-declared, cited IAM actions** (never fabricated), grounded code examples, a FISC cloud-residency lens, and a per-deployment audit trail (opaque `dep:<sha8>` + provenance status). On 0-hit/rejected → out-of-scope safe answer | emits safe answer on `error_code` / no references |

> **Conditional edges do not propagate across the subgraph boundary** (GraphNode wraps the inner graph),
> so the inner topology is a **static linear backbone with per-node skip guards** — the portable Cat 2 form
> shipped across the fleet. `add_conditional_edges` is intentionally **not** used inside the subgraph.

### Data Flow

```
START → initialize → pre_process → main(GraphNode) → {route} → post_process → finalize → END
                                        ↓ (retry, max 3)
                                     pre_process
```

**Degraded / rejected path (mandatory contract).** An injection marker, an oversize payload, empty input,
or zero matched deployment references never sets `status=ERROR`. Instead the node returns `status=SUCCESS`
**plus an `error_code`** (`INJECTION_REJECTED` / `INPUT_TOO_LONG` / `INPUT_REJECTED` / `NO_REFERENCE`). This is
deliberate: in the production framework `status=ERROR` short-circuits `AgentBaseGraph.route()` straight to
`finalize`, so **`main`/`post_process` would be skipped and the mandatory DRAFT disclaimer + S-3 redaction
+ S-4 terminal audit would never run**. With `SUCCESS + error_code`, `route()` reaches `post_process`,
which always emits the out-of-scope safe answer, disclaimer, and audit. On the injection/oversize path
`pre_process` **discards the offending body** (`validated_input="{}"`, `user_input` cleared) so no rejected
content is ever processed. Because `GraphNode.extract_input()` passes only `validated_input` into the fresh
inner state, `merge_output` surfaces the **outer** `error_code` first (`state.get("error_code") or
sub_result.get("error_code")`) so a pre-stage rejection code survives to the terminal S-4 audit.

### State Definition (`src/schemas/state.py`)

| Field | Type | Purpose | Required |
|-------|------|---------|----------|
| validated_input | NotRequired[str] | JSON `{query, deployments[], deployment_target, jurisdictions, query_namespace}` from pre_process (credential/My-Number redacted; deployment ids tokenized; provenance resolved) | no |
| input_format | NotRequired[str] | `json` / `text` / `empty` / `rejected` | no |
| enriched_context | NotRequired[str] | JSON `{source, channel}` (read-only caller context) | no |
| masked_request_fields | NotRequired[str] | JSON list of the request field names (`query` / `jurisdictions` / `deployment_target`) that reached pre_process as `[MASKED]` — names only, never values | no |
| routed_namespaces | NotRequired[str] | JSON KB namespaces routed for retrieval (deploy / iam / bedrock / fisc) | no |
| retrieved_docs | NotRequired[str] | JSON retrieved deployment references (doc_id, source, article, citation, guidance, iam_actions, …) | no |
| retrieval_hit_count | NotRequired[int] | references matched (0 → out-of-scope safe answer) | no |
| analyzed_docs | NotRequired[str] | JSON per-reference applicability annotation vs caller deployment context | no |
| result | NotRequired[str] | JSON assembled deployment-advisory deliverable (answer + IAM template + code + FISC + audit trail) | no |
| formatted_output | NotRequired[str] | JSON final response envelope (deliverable + disclaimer) | no |
| disclaimer | NotRequired[str] | mandatory DRAFT "verify before applying" disclaimer | no |
| audit_logged | NotRequired[bool] | True once terminal audit event emitted | no |
| error_code | NotRequired[str] | `INPUT_REJECTED` / `INJECTION_REJECTED` / `INPUT_TOO_LONG` / `NO_REFERENCE` / `CITATION_INCOMPLETE` | no |
| error_message | NotRequired[str] | operator-facing detail | no |

**State Constraints (mandatory):**
- Flat TypedDict only (primitives + JSON-serializable types); complex fields serialized as JSON strings (ADR-005)
- No JWT, API keys, credentials in State (checkpoint DB leakage) — pre_process input hygiene redacts them from
  **every** supplied free-text field (query + deployment descriptors)
- **Opaque-id boundary — privacy tokenize vs provenance validation are SEPARATE (primary defense = input side).**
  - **Privacy (identifiers).** A deployment `deployment_id`/`agent_id`/`id` is **unconditionally** tokenized to
    `dep:<sha8>` — there is NO syntactic "this looks like a safe id" passthrough (a name such as `Alice` /
    `prod-agent` / `TaroYamada` with no spaces/symbols is tokenized like any other value). Tokenizing hides PII;
    it makes **no** claim that the value is authorized.
  - **Provenance (citations).** A caller `source` becomes a grounded citation **only when it resolves to an
    authorized deployment/IaC system of record** (`AUTHORIZED_PROVENANCE_SYSTEMS`, the deploying org's / CoE's
    trusted-context registry — a *semantic* allowlist of authorized systems, not a character class). Then it
    is privacy-tokenized to `src:<sha8>` (raw label never verbatim). Any other value — a deployment name,
    `unknown`, a fabricated string, **or a value that merely looks like a surrogate (`src:1a2b3c4d`)** — is
    **not** verifiable provenance → `None` → S-3 blocks the per-deployment audit trail as `CITATION_INCOMPLETE`
    (fail-closed). "Tokenized" is never sufficient for a citation. No synthetic provenance is fabricated.
  - Provenance is resolved **exactly once** (S-1 / pre_process); the inner workflow trusts that resolved value
    verbatim and never re-resolves (re-resolving an internal `src:<sha8>` would, correctly, reject it), so a
    forged surrogate can never imitate an internal one downstream.
- InvocationContext via `config["configurable"]` only (not in State)
- No Pydantic models, dataclass, arbitrary Python objects (msgpack incompatible)

## Framework Utilization

### Shared Components Used
- [x] InvocationContext (correlation_id, session_id, caller_trust_level) — read-only inside nodes
- [x] **S-2**: `_extra_security_gate_input(self, state) -> dict` on `PreProcessNode` — size cap +
      prompt-injection markers + field-level input hygiene. SDK 1.0.0 contract: **MUST NOT raise, and MUST
      NOT return `status=ERROR`**. A rejection is surfaced as a **degraded `SUCCESS + error_code`**
      (`INJECTION_REJECTED` / `INPUT_TOO_LONG`); `pre_process.execute()` re-checks the same conditions
      (the `@final` hook is not invoked by the local stub framework) and discards the offending body so the
      pipeline reaches `post_process` and always emits the disclaimer + audit. **MUST NOT override
      `_security_gate_input()`** — `TypeError` at class definition.
- [x] **S-3**: `PostProcessNode.execute()` enforces **fail-closed citation completeness** — a grounded
      advisory (`status_kind == "deployment_advisory"`) with no reference citation, or with any supplied
      deployment whose provenance did not resolve, is not presented; it degrades to a safe `needs_review` answer
      (deliverable body withheld, `error_code=CITATION_INCOMPLETE`, still SUCCESS so the disclaimer + S-4 audit
      run). Reference citations come only from the KB (never fabricated); the least-privilege IAM template is
      composed only from KB-declared, cited IAM actions; deployment provenance is an allowlisted opaque
      reference validated once in pre_process. A whole-report redactor re-redacts credential / My-Number /
      email / phone leakage. `_extra_security_gate_output(self, result) -> dict` additionally verifies the
      mandatory DRAFT disclaimer is present and MAY raise to block. **MUST NOT override
      `_security_gate_output()`** — `TypeError` at class definition.
- [x] **S-4**: `emit_trace_event()` inside **every** `execute()` path (including skip / safe branches) —
      domain event only (never `node_start`/`node_complete` which `BaseNode.__call__()` emits automatically).
      Counts / routed namespaces / error_code only — never the raw caller query, a deployment name, or provenance.

> **S-2/S-3 gate behaviour by node type (ADR-017):**
> - `FunctionNode` subclass (`PreProcessNode`, `PostProcessNode`, and the four inner nodes) → framework
>   `@final` gate always runs automatically; extend via `_extra_security_gate_input()` / `_extra_security_gate_output()` only.
> - `GraphNode` (`DeploymentAdvisoryWorkflowGraphNode`) → deliberate no-op (the wrapped subgraph nodes' gates already apply).

### Trust Level (S-1)
All concrete `FunctionNode` subclasses declare `required_trust_level = TrustLevel.VERIFIED_EXTERNAL`
explicitly (gate-trust-level-check), matching the agent-level `required_trust_level` in `config/agent.yaml`.
`GraphNode` is excluded by design (delegated S-1).

### Determinism (no LLM)
The template is **fully deterministic** — no LLM is used. Namespace routing, BM25-lite reference retrieval,
reference-to-context mapping, least-privilege IAM template composition, code-example collection, and deliverable
synthesis are pure tokenization + keyed KB composition (the deployment KB in `src/services/service.py`), so
every answer is reproducible, auditable, and grounded in a cited AWS-official reference. `config/agent.yaml`
declares no model and `pyproject.toml` declares no LLM dependency. The agent is **read-only** — it answers
deployment *questions* only and never executes a deployment or applies an IAM policy.

### Least-privilege IAM anti-hallucination (SoT §7/§11 risk mitigation)
IAM permission-template generation is security-sensitive (over-privilege risk on mis-generation). The template
mitigates this **by design**: every IAM action in the emitted policy template is drawn **only** from the
KB-declared `iam_actions` of a retrieved, cited reference (no LLM, no fabricated action), each statement carries
its source citation, no `Resource: "*"` wildcard is emitted (a `REPLACE_WITH_SPECIFIC_RESOURCE_ARN` placeholder
enforces least-privilege scoping), and the mandatory DRAFT "verify before applying" disclaimer marks the
template as a decision aid — the final IAM grant is an authorized cloud/security reviewer's.

### Platform masking of request terms (S-2)
The platform's personal-data pass runs before this template and replaces any run of two or more Title-Case
words in the request with `[MASKED]`; the template cannot switch it off. Measured on AgentCore 1.0.3: "Amazon
Bedrock Guardrails" becomes `[MASKED]`, so "What IAM permissions does our agent need to use Amazon Bedrock
Guardrails?" retrieves no guardrails reference and the IAM template lacks `bedrock:ApplyGuardrail`; "United
States" and a `deployment_target` of "Amazon Bedrock" are masked the same way ("Bedrock AgentCore" is not).
pre_process records which request fields (`query` / `jurisdictions` / `deployment_target`) contain the token in
`masked_request_fields` — a masked `deployment_target` that still normalises ("[MASKED] AgentCore" →
`bedrock_agentcore`) is not listed. post_process then adds the stable code `QUERY_TERMS_MASKED` to the envelope's
`limitations` list (codes only; `[]` when nothing was masked), sets `confidence: "low"`, and appends to `message`
which fields were masked and how to rephrase. When a masked request retrieves nothing, `status_kind` is
`not_evaluated` instead of `out_of_scope`: nothing matching a partly erased question is not evidence that it is
outside the KB. The trade-off is that an off-topic question containing a masked name is also `not_evaluated`.

### Human decision boundary (advisory-only, no HumanApprovalGate node)
This template is **advisory-only**: it composes a DRAFT deployment answer + IAM policy template + FISC lens and
never executes a deployment, applies an IAM policy, or renders a binding determination. There is **no
`human_gate` node** in the inner workflow; the human decision boundary is enforced at output by the **mandatory
DRAFT disclaimer** ("this is a draft — verify before applying; the final IAM grant / deployment decision is an
authorized cloud/security reviewer's"). The S-3 gate blocks any output missing that disclaimer.

### Composition Pattern
- **Pattern**: GraphNode (subgraph) — outer `AgentBaseGraph` 5-slot backbone with a `GraphNode` in the `main`
  slot wrapping an inner `BaseGraph` (`DeploymentAdvisoryWorkflow`).
- **Composition target**: `src/graph/domain_workflow_graph.py::DeploymentAdvisoryWorkflow`
- **Subgraph caching**: `get_subgraph()` caches the inner graph on the **class attribute** (`DeploymentAdvisoryWorkflowGraphNode._subgraph`, not `self` — avoids mutable node-instance state per §9; built once).
- **Error propagation strategy**: `propagate` — an inner ERROR surfaces as `SubgraphError`; the deterministic
  degraded path (0-reference / rejected) instead returns `status = SUCCESS + error_code` and a safe answer.

## Import Isolation Confirmation
- [x] Template does not import agenticstar-platform SDK (Level 0) — PB-4
- [x] Import targets: `framework/` and `shared/` only (via `src.utils.audit` fallback shim)

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | **AgentBaseGraph** | AutonomousBaseGraph | **AgentBaseGraph** | Fixed multi-step workflow, no autonomous reasoning loop — Cat 2 |
| Composition pattern | FunctionNode-in-main (Cat 1) | **GraphNode-in-main (Cat 2)** | **GraphNode-in-main** | Deployment-advisory workflow has 4 ordered steps → encapsulate behind a subgraph |
| Inner topology | conditional edges | **linear + skip guards** | **linear + skip guards** | Conditional edges do not propagate across the subgraph boundary |
| Retrieval / synthesis | LLM narrative | **deterministic BM25-lite + keyed KB composition** | **deterministic** | Auditable, reproducible; grounded in cited AWS-official references — see Determinism |
| IAM template source | LLM-generated permissions | **KB-declared cited actions only** | **KB-declared cited actions** | Anti-hallucination — no over-privileged permission is fabricated (SoT §7/§11) |
| Human sign-off | agent applies IAM / deploys | **advisory-only DRAFT disclaimer** | **advisory-only DRAFT disclaimer** | The final IAM grant / deployment decision is a human cloud/security reviewer's, never the agent's |
| Degraded path | status=ERROR | **status=SUCCESS + error_code** | **SUCCESS + error_code** | ERROR would skip post_process (S-3/S-4) in production FW |

## Open Items (deferred to Stage ③ Implementation MR)
- Node `execute()` bodies (`ingest_scope`, `knowledge_retrieve`, `interpret_analyze`, `answer_synthesize`,
  rewritten `pre_process` / `post_process`), the inner `DeploymentAdvisoryWorkflow`, `DeploymentAdvisoryService`
  (deployment KB + BM25-lite retrieval + namespace routing + `safe_identifier` + `resolve_provenance` +
  least-privilege IAM composition + deliverable synthesis), `src/utils/audit.py` (S-4 shim), unit / integration
  / boundary tests, and docs/03 + docs/07 land in the Stage ③ implementation MR. This design MR ships
  `docs/02_design.md` + `src/schemas/state.py` only.
