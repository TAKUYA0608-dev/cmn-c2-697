"""CMN-C2-697 — inner workflow step 4: answer_synthesize (CodeExampleExtract / assemble deliverable).

Composes the deployment-advisory deliverable — cited answer sections (one per retrieved reference), a
**least-privilege IAM policy template composed only from KB-declared, cited IAM actions** (never fabricated),
grounded code examples, a FISC cloud-residency lens, and a per-deployment audit trail (opaque `dep:<sha8>` +
provenance status). On the 0-hit / rejected branch it emits the out-of-scope safe answer — no fabricated
deployment advice or IAM permission.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import DeploymentAdvisoryService
from src.utils.audit import emit_trace_event

_OUT_OF_SCOPE = (
    "ご質問に該当する AWS デプロイ/運用リファレンスが KB(AWS Agent Toolkit / Amazon Bedrock AgentCore / "
    "Bedrock / IAM / FISC)に見つかりませんでした。デプロイ対象(AgentCore Runtime / Bedrock)や論点"
    "(IAM 最小権限 / モデルアクセス / FISC リージョン所在 / 可観測性 など)を具体化のうえ再度お問い合わせください。"
)


class AnswerSynthesizeNode(FunctionNode):
    """Compose the deployment-advisory deliverable with citations (or the safe answer on 0-hit)."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        refs = json.loads(state.get("retrieved_docs") or "[]")
        if state.get("error_code") or not refs:
            emit_trace_event("answer_synthesize.safe", {"reason": state.get("error_code") or "no_reference"}, state)
            report: dict[str, Any] = {
                "status_kind": "out_of_scope",
                "message": _OUT_OF_SCOPE,
                "answer_sections": [],
                "iam_policy_template": None,
                "code_examples": [],
                "fisc_residency": None,
                "deployment_audit_trail": [],
                "citations": [],
            }
            return {"result": json.dumps(report, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}

        slots = json.loads(state.get("validated_input") or "{}")
        analyzed = json.loads(state.get("analyzed_docs") or "[]")
        audit_trail = DeploymentAdvisoryService.build_deployment_audit_trail(slots.get("deployments") or [])
        report = DeploymentAdvisoryService.synthesize(
            slots.get("query_namespace") or [], slots.get("deployment_target"), refs, analyzed, audit_trail
        )
        emit_trace_event(
            "answer_synthesize.complete",
            {
                "section_count": len(report["answer_sections"]),
                "citation_count": len(report["citations"]),
                "iam_statement_count": len((report.get("iam_policy_template") or {}).get("Statement", [])),
                "deployment_count": len(audit_trail),
                "unverified_deployments": sum(1 for a in audit_trail if a["citation"] is None),
            },
            state,
        )
        return {"result": json.dumps(report, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}
