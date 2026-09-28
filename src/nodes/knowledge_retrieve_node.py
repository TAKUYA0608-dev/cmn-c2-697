"""CMN-C2-697 — inner workflow step 2: knowledge_retrieve (HybridRetrieve).

Deterministic BM25-lite retrieval over the seeded AWS deployment/ops reference KB (AWS Agent Toolkit / Amazon
Bedrock AgentCore / Bedrock / IAM / FISC), scoped by the routed namespaces. Sets `retrieval_hit_count`;
**0 hits (rejected input or out-of-domain query) routes to the out-of-scope safe answer** — the agent never
fabricates deployment advice or an IAM permission that is not grounded in a cited AWS-official reference.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import DeploymentAdvisoryService
from src.utils.audit import emit_trace_event


class KnowledgeRetrieveNode(FunctionNode):
    """Retrieve grounded AWS-deployment references for the query."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        slots = json.loads(state.get("validated_input") or state.get("user_input") or "{}")
        canonical = json.dumps(slots, ensure_ascii=False)
        query = slots.get("query") or ""
        namespaces = json.loads(state.get("routed_namespaces") or "null")
        if namespaces is None:
            namespaces = slots.get("query_namespace") or []

        if state.get("error_code") or not query.strip():
            emit_trace_event("knowledge_retrieve.skip", {"reason": state.get("error_code") or "empty_query"}, state)
            return {
                "validated_input": canonical,
                "retrieved_docs": "[]",
                "retrieval_hit_count": 0,
                "error_code": state.get("error_code") or "NO_REFERENCE",
                "status": AgentStatus.SUCCESS.value,
            }

        refs = DeploymentAdvisoryService.retrieve(query, namespaces)
        emit_trace_event("knowledge_retrieve.complete", {"hit_count": len(refs), "namespaces": namespaces}, state)
        out = {
            "validated_input": canonical,
            "retrieved_docs": json.dumps(refs, ensure_ascii=False),
            "retrieval_hit_count": len(refs),
            "status": AgentStatus.SUCCESS.value,
        }
        if not refs:
            out["error_code"] = "NO_REFERENCE"
        return out
