"""CMN-C2-697 — Agent state (Enterprise AWS AgentCore Deployment Q&A, Cat 2).

ADR-005: State is a flat TypedDict — never a validation/BaseModel instance. Complex fields are stored
as JSON strings (``NotRequired[str]`` + ``# JSON:``); nodes ``json.dumps`` on write / ``json.loads`` on read.

Advisory posture: the agent answers AWS-deployment *questions* against a seeded, AWS-official deployment/ops
reference KB (AWS Agent Toolkit / Amazon Bedrock AgentCore / Bedrock / IAM / FISC) — it is read-only and never
executes a deployment or applies an IAM policy. A caller-supplied deployment descriptor is reduced to an opaque
``dep:<sha8>`` surrogate (``safe_identifier``) and its provenance is resolved to a grounded ``src:<sha8>``
citation only when it names an authorized deployment/IaC system of record (``resolve_provenance``) — otherwise
``None``, and S-3 blocks the per-deployment audit trail as fail-closed. Any free-text field a caller supplies
(query / deployment descriptor) is hygiened at S-1 so a credential / My-Number / email / phone never persists
in State. The least-privilege IAM policy template is composed **only** from KB-declared, cited IAM actions
(never fabricated) so no over-privileged permission is hallucinated.

All agent-specific fields are NotRequired (populated progressively; absent at empty-start invoke).
"""

from __future__ import annotations


from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Agent state for the AWS AgentCore deployment-advisory Q&A workflow."""

    # ── pre_process (QueryNormalize, S-1 validated request + field-level hygiene) ──────────────
    validated_input: str  # JSON: {query, deployments[], deployment_target, jurisdictions, query_namespace}
    input_format: str  # "json" | "text" | "empty" | "rejected"
    enriched_context: str  # JSON: {source, channel} (read-only caller context)
    masked_request_fields: str  # JSON: [field name] masked by the platform's S-2 pass (names only)

    # ── inner workflow (ingest_scope → knowledge_retrieve → interpret_analyze → answer_synthesize) ──
    routed_namespaces: str  # JSON: KB namespaces routed for retrieval (deploy / iam / bedrock / fisc)
    retrieved_docs: str  # JSON: [{doc_id, source, article, citation, guidance, iam_actions, ...}]
    retrieval_hit_count: int  # deployment references retrieved (0 → out-of-scope safe answer)
    analyzed_docs: str  # JSON: [{doc_id, applicability, applies}] per-doc context annotation
    result: str  # JSON: assembled deployment-advisory deliverable

    # ── post_process (S-3 gate + S-4 audit) ─────────────────────────────────────────────────────
    formatted_output: str  # JSON: final response envelope (deliverable + disclaimer)
    disclaimer: str  # mandatory DRAFT "verify before applying" advisory disclaimer
    audit_logged: bool  # True once the terminal audit event is emitted

    # ── degraded-path signalling (SUCCESS + error_code, never status=ERROR) ──────────────────────
    error_code: str  # INPUT_REJECTED | INJECTION_REJECTED | INPUT_TOO_LONG
    #                                       | NO_REFERENCE | CITATION_INCOMPLETE
    error_message: str  # operator-facing detail
