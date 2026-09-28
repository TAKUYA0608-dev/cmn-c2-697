"""CMN-C2-697 — inner workflow step 3: interpret_analyze (ResponseGenerate / interpret).

Deterministic mapping of each retrieved reference to the caller deployment context (deployment_target /
jurisdictions) → a per-reference applicability annotation. Skips (no-op) on rejected / 0-hit input.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import DeploymentAdvisoryService
from src.utils.audit import emit_trace_event


class InterpretAnalyzeNode(FunctionNode):
    """Annotate each retrieved reference with its applicability to the caller deployment context."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code") or state.get("retrieval_hit_count", 0) == 0:
            emit_trace_event("interpret_analyze.skip", {"reason": state.get("error_code") or "no_reference"}, state)
            return {}
        refs = json.loads(state.get("retrieved_docs") or "[]")
        slots = json.loads(state.get("validated_input") or "{}")
        target = slots.get("deployment_target")
        jurisdictions = slots.get("jurisdictions") or []
        analyzed = [DeploymentAdvisoryService.map_reference(r, target, jurisdictions) for r in refs]
        emit_trace_event(
            "interpret_analyze.complete",
            {"count": len(analyzed), "applicable": sum(1 for m in analyzed if m["applies"])},
            state,
        )
        return {"analyzed_docs": json.dumps(analyzed, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}
