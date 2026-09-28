"""CMN-C2-697 — post_process node: ResponseValidate (S-3 output gate + S-4 audit).

S-3 (fail-closed): **enforce** citation completeness — a grounded deployment advisory that has no reference
citation, or that references a supplied deployment whose provenance did not resolve to an authorized system of
record, is never presented; it degrades to a safe `needs_review` answer with the deliverable body withheld
(`error_code=CITATION_INCOMPLETE`, still SUCCESS so post/S-4/disclaimer run). Re-redact any credential /
My-Number / email / phone leakage (defense-in-depth), and append the mandatory DRAFT advisory disclaimer — the
answer + IAM template are a decision aid, not a production-ready grant; the final IAM permission, FISC-residency
decision, and deployment are an authorized cloud / security reviewer's ("verify before applying"). S-4: emit an
audit event (routed namespaces / counts / verdict / error_code only — never the raw query, a deployment name,
or provenance). Runs on the full deliverable, the citation-blocked branch, and the out-of-scope safe branch.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar, cast

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import QUERY_TERMS_MASKED
from src.utils.audit import emit_trace_event

_DISCLAIMER = (
    "本回答は、AWS 公式ドキュメント(AWS Agent Toolkit / Amazon Bedrock AgentCore / Bedrock / IAM / FISC 安全"
    "対策基準)に基づく参考用の DRAFT デプロイ助言であり、生成された IAM ポリシーテンプレートはそのまま本番適用"
    "できる最小権限保証ではありません。IAM 権限の付与・スコープ設定、リージョン/データ所在(FISC)対応、本番"
    "デプロイの可否は、必ず認可されたクラウド / セキュリティ担当者の確認(verify before applying)を経てください。"
    "本エージェントは助言のみを行い、デプロイやポリシー適用の実行は行いません。"
)

_CITATION_INCOMPLETE_MSG = (
    "助言の一部に検証可能な出典(AWS 公式リファレンス / デプロイの provenance)が確認できなかったため、"
    "根拠不十分な助言草案の提示を差し控えました。各デプロイに認可されたデプロイ/IaC 登録先の provenance を"
    "付与のうえ再実行してください。"
)
# Platform masking (S-2): the explanation for the `limitations` code QUERY_TERMS_MASKED. `{fields}` lists the
# request field names that reached the agent masked (never their values).
_MASKED_NOTE = (
    "注: 問い合わせの一部({fields})はプラットフォームの個人情報保護処理により [MASKED] に置き換えられてから"
    "検索されました(連続する大文字始まりの語、例: 'Amazon Bedrock Guardrails' を人名として扱うため)。"
    "伏せられた語でしか一致しないリファレンスは取得できないため、回答セクションと IAM ポリシーテンプレートに"
    "問い合わせの内容が欠けている可能性があります。製品名を小文字で(例: 'bedrock guardrails')再度お問い合わせください。"
)
_NOT_EVALUATED_MSG = (
    "問い合わせの一部({fields})がプラットフォームの個人情報保護処理により [MASKED] に置き換えられたため、"
    "KB のリファレンスと照合できませんでした。KB の対象外と判定したものではありません。製品名を小文字で"
    "(例: 'bedrock guardrails')再度お問い合わせください。AWS AgentCore のデプロイ / IAM / Bedrock / FISC "
    "以外のご質問は、本エージェントの対象外です。"
)

_NEEDS_REVIEW_NOTE = (
    "Grounding could not be verified for every reference / deployment; the draft advisory is withheld pending "
    "valid provenance and authorized cloud / security review."
)

# S-3 defense-in-depth: re-redact secrets / contact info that could leak into any free-text field of the
# deliverable (applied to the whole serialized report before it becomes the output envelope).
_SECRET = re.compile(r"\b(?:sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}|\d{12})\b")
_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}")
_PHONE = re.compile(r"(?<![\d.])(?:(?:\+81[-\s]?\d{1,4}|0\d{1,4})[-\s]?\d{1,4}[-\s]?\d{3,4})(?![\d.])")
_REDACTORS = (_SECRET, _EMAIL, _PHONE)


def _redact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Serialize → redact secret / contact patterns → deserialize (whole-report defense-in-depth)."""
    text = json.dumps(report, ensure_ascii=False)
    for pattern in _REDACTORS:
        text = pattern.sub("[REDACTED]", text)
    return cast(dict[str, Any], json.loads(text))


class PostProcessNode(FunctionNode):
    """Verify citation completeness, redact leakage, append the DRAFT advisory disclaimer, emit audit."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        """S-3 preservation check: the DRAFT advisory disclaimer must be present in the output envelope.

        SDK 1.0.0 contract: receives the **result dict from `execute()`**; returns the (possibly filtered)
        result. MAY raise to block an output missing the mandatory disclaimer.
        """
        out = result.get("formatted_output", "")
        if out and "参考" not in out and "DRAFT" not in out:
            raise ValueError("S-3: DRAFT advisory disclaimer missing from output")
        return dict(result)

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        report: dict[str, Any] = _redact_report(json.loads(state.get("result", "{}") or "{}"))
        # Platform masking (S-2): request fields that reached retrieval as [MASKED]. A masked request is never
        # presented as complete, and "nothing matched" on a masked request is "not evaluated", not out of scope.
        masked_fields: list[str] = json.loads(state.get("masked_request_fields") or "[]")
        limitations = [QUERY_TERMS_MASKED] if masked_fields else []
        if masked_fields:
            fields = ", ".join(masked_fields)
            if report.get("status_kind") == "out_of_scope":
                report["status_kind"] = "not_evaluated"
                report["message"] = _NOT_EVALUATED_MSG.format(fields=fields)
            else:
                report["message"] = f"{report.get('message') or ''} {_MASKED_NOTE.format(fields=fields)}".strip()

        grounded = report.get("status_kind") == "deployment_advisory"
        citations = report.get("citations", [])
        answer_sections = report.get("answer_sections", [])
        audit_trail = report.get("deployment_audit_trail", [])
        iam_template = report.get("iam_policy_template") or {}
        iam_statements = iam_template.get("Statement", []) if isinstance(iam_template, dict) else []
        code_examples = report.get("code_examples", [])
        fisc = report.get("fisc_residency")
        # S-3 per-member authoritative correspondence: a grounded advisory needs ≥1 reference citation, every
        # supplied deployment must carry a resolved provenance citation, AND every emitted deliverable member
        # (answer section, IAM statement, code example, FISC section) must carry a citation that maps to an
        # authoritative top-level citation. A member whose citation is missing, or belongs to a DIFFERENT
        # reference than the deliverable's top-level citations, fails closed — a partially / cross-cited
        # deliverable is never presented (presence of *some* citation is not sufficient). Vacuously complete
        # when not grounded / no deployments.
        cited_tokens = {c.get("citation") for c in citations if c.get("citation")}
        citation_complete = (not grounded) or (
            bool(citations)
            and bool(answer_sections)
            and all(a.get("citation") for a in audit_trail)
            and all(s.get("citation") in cited_tokens for s in answer_sections)
            and all(st.get("_citation") in cited_tokens for st in iam_statements)
            and all(ex.get("citation") in cited_tokens for ex in code_examples)
            and (fisc is None or fisc.get("citation") in cited_tokens)
        )

        if grounded and not citation_complete:
            error_code = state.get("error_code") or "CITATION_INCOMPLETE"
            blocked = {
                "status_kind": "needs_review",
                "query_namespaces": report.get("query_namespaces", []),
                "answer_sections": [],  # incomplete deliverable body withheld
                "iam_policy_template": None,
                "code_examples": [],
                "fisc_residency": None,
                "deployment_audit_trail": [],
                "human_review": {
                    "required": True,
                    "status": "pending_cloud_security_review",
                    "note": _NEEDS_REVIEW_NOTE,
                },
                "citations": [],
                "citation_complete": False,
                "limitations": limitations,
                "message": (
                    f"{_CITATION_INCOMPLETE_MSG} {_MASKED_NOTE.format(fields=', '.join(masked_fields))}"
                    if masked_fields
                    else _CITATION_INCOMPLETE_MSG
                ),
                "disclaimer": _DISCLAIMER,
            }
            emit_trace_event(
                "response_validate.citation_blocked",
                {
                    "section_count": len(answer_sections),
                    "deployment_count": len(audit_trail),
                    "limitations": limitations,
                    "error_code": error_code,
                },
                state,
            )
            return {
                "formatted_output": json.dumps(blocked, ensure_ascii=False),
                "disclaimer": _DISCLAIMER,
                "audit_logged": True,
                "error_code": error_code,
                "status": AgentStatus.SUCCESS.value,
            }

        formatted = {
            "status_kind": report.get("status_kind"),
            "query_namespaces": report.get("query_namespaces", []),
            "deployment_target": report.get("deployment_target"),
            "sources_covered": report.get("sources_covered", []),
            "answer_sections": answer_sections,
            "iam_policy_template": report.get("iam_policy_template"),
            "code_examples": report.get("code_examples", []),
            "fisc_residency": report.get("fisc_residency"),
            "deployment_audit_trail": audit_trail,
            "citations": citations,
            "citation_complete": citation_complete,
            "limitations": limitations,
            "confidence": "low" if masked_fields else report.get("confidence"),
            "message": report.get("message"),
            "disclaimer": _DISCLAIMER,
        }
        emit_trace_event(
            "response_validate.complete",
            {
                "status_kind": report.get("status_kind"),
                "section_count": len(answer_sections),
                "deployment_count": len(audit_trail),
                "citation_count": len(citations),
                "citation_complete": citation_complete,
                "limitations": limitations,
                "error_code": state.get("error_code"),
            },
            state,
        )
        return {
            "formatted_output": json.dumps(formatted, ensure_ascii=False),
            "disclaimer": _DISCLAIMER,
            "audit_logged": True,
            "status": AgentStatus.SUCCESS.value,
        }
