"""CMN-C2-697 — inner workflow step 1: ingest_scope (DocNamespaceRoute / scope).

Reads the normalized request, surfaces the routed KB namespace(s) (deploy / iam / bedrock / fisc) computed at
S-1, and canonicalizes the request into the inner state so downstream inner nodes see it. Deterministic — no
LLM. Skips (still emits) on rejected input.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.utils.audit import emit_trace_event


class IngestScopeNode(FunctionNode):
    """Surface the retrieval scope (routed namespaces) and canonicalize the request for the inner workflow."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        slots = json.loads(state.get("validated_input") or state.get("user_input") or "{}")
        canonical = json.dumps(slots, ensure_ascii=False)
        namespaces = slots.get("query_namespace") or []
        if state.get("error_code"):
            emit_trace_event("ingest_scope.skip", {"reason": state.get("error_code")}, state)
            return {"validated_input": canonical, "routed_namespaces": "[]", "status": AgentStatus.SUCCESS.value}
        emit_trace_event("ingest_scope.complete", {"namespace_count": len(namespaces), "namespaces": namespaces}, state)
        return {
            "validated_input": canonical,
            "routed_namespaces": json.dumps(namespaces, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
