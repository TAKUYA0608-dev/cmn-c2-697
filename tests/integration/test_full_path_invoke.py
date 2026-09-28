"""Production path with the platform's S-2 personal-data masking active.

The framework input gate (final, runs before every node of this template) replaces any run of two or more
Title-Case words in `user_input` with "[MASKED]" — "Amazon Bedrock Guardrails", "Amazon Bedrock" and
"United States" included. Measured 2026-09-24 on AgentCore 1.0.3: "What IAM permissions does our agent need to
use Amazon Bedrock Guardrails?" returned a least-privilege IAM template without bedrock:ApplyGuardrail at
confidence "medium", and "Explain Amazon Bedrock Guardrails setup." was answered "out_of_scope". These tests call
the real `Graph().invoke()` as a VERIFIED_EXTERNAL caller so the gate runs exactly as in production.
"""

from __future__ import annotations

import json
from typing import Any

from framework.nodes.function_node import detect_pii, mask_pii
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph

_MASKED_Q = "What IAM permissions does our agent need to use Amazon Bedrock Guardrails?"
_JSON_QUERY = "what are the deployment steps and IAM role?"


def _env(text: str) -> dict[str, Any]:
    ctx = InvocationContext(caller_id="integration-test", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
    out = Graph().invoke(text, ctx=ctx)
    assert str(out.get("status")).lower().endswith("success"), out.get("status")
    body = out["output"]
    env: dict[str, Any] = json.loads(body) if isinstance(body, str) else body
    return env


def _platform_view(text: str) -> str:
    """What the platform's input gate turns `text` into before this template sees it."""
    return str(mask_pii(text, detect_pii(text)))


def _grants_apply_guardrail(env: dict[str, Any]) -> bool:
    return "bedrock:ApplyGuardrail" in json.dumps(env.get("iam_policy_template"))


class TestPlatformMaskedQuery:
    def test_a_masked_product_name_is_flagged_and_low_confidence(self) -> None:
        assert _platform_view(_MASKED_Q) == "What IAM permissions does our agent need to use [MASKED]?", "precondition"
        assert _grants_apply_guardrail(_env(_MASKED_Q.lower())), "precondition: lower case reaches guardrails"
        env = _env(_MASKED_Q)
        assert not _grants_apply_guardrail(env), "precondition: the product name never reached retrieval"
        assert env["status_kind"] == "deployment_advisory", env
        assert env["confidence"] == "low", env
        assert env["limitations"] == ["QUERY_TERMS_MASKED"], env
        assert "[MASKED]" in env["message"] and "query" in env["message"], env["message"]

    def test_a_fully_masked_in_domain_question_is_not_evaluated_rather_than_out_of_scope(self) -> None:
        question = "Amazon Bedrock Guardrails Setup"
        assert _platform_view(question) == "[MASKED]", "precondition: the whole question is masked"
        assert _env(question.lower())["status_kind"] == "deployment_advisory", "precondition: in-domain words"
        env = _env(question)
        assert env["status_kind"] == "not_evaluated", env
        assert env["answer_sections"] == [] and env["citations"] == [], env
        assert env["limitations"] == ["QUERY_TERMS_MASKED"], env
        assert env["confidence"] == "low", env
        assert "対象外と判定したものではありません" in env["message"], env["message"]

    def test_an_unmasked_non_matching_term_plus_a_masked_term_is_not_a_confident_out_of_scope(self) -> None:
        # The unmasked words ("tune quantum annealing") reach retrieval and match nothing; the product name is
        # what would have matched, but it was masked. That is not evidence the question is out of scope.
        question = "How do I tune quantum annealing with Amazon Bedrock Guardrails?"
        assert _platform_view(question) == "How do I tune quantum annealing with [MASKED]?", "precondition"
        assert (
            _env("How do I tune quantum annealing?")["status_kind"] == "out_of_scope"
        ), "precondition: the unmasked words alone match nothing"
        env = _env(question)
        assert env["status_kind"] == "not_evaluated", env
        assert env["limitations"] == ["QUERY_TERMS_MASKED"], env
        assert env["confidence"] == "low", env

    def test_masked_target_and_jurisdiction_fields_are_reported(self) -> None:
        plain = {"query": _JSON_QUERY, "deployment_target": "bedrock", "jurisdictions": ["us"]}
        masked = dict(plain, deployment_target="Amazon Bedrock", jurisdictions=["United States"])
        control = _env(json.dumps(plain))
        env = _env(json.dumps(masked))
        assert control["deployment_target"] == "bedrock_agentcore", control
        assert env["deployment_target"] is None, "precondition: the masked target no longer normalises"
        assert env["confidence"] == "low", env
        assert env["limitations"] == ["QUERY_TERMS_MASKED"], env
        assert "jurisdictions, deployment_target" in env["message"], env["message"]

    def test_a_masked_target_that_still_normalises_is_not_flagged(self) -> None:
        request = {"query": _JSON_QUERY, "deployment_target": "Amazon Bedrock AgentCore", "jurisdictions": ["us"]}
        assert "[MASKED] AgentCore" in _platform_view(json.dumps(request)), "precondition: part of it is masked"
        env = _env(json.dumps(request))
        assert env["deployment_target"] == "bedrock_agentcore", env
        assert env["limitations"] == [], env
        assert env["confidence"] == "medium", env

    def test_an_unmasked_question_is_unchanged(self) -> None:
        env = _env(_MASKED_Q.lower())
        assert env["limitations"] == []
        assert env["confidence"] == "medium"
        assert _grants_apply_guardrail(env)
        assert "[MASKED]" not in env["message"]

    def test_an_unmasked_off_topic_question_stays_out_of_scope(self) -> None:
        env = _env("recommend a good ramen shop in Osaka")
        assert env["status_kind"] == "out_of_scope"
        assert env["limitations"] == []
        assert env["confidence"] is None

    def test_an_off_topic_question_with_a_masked_name_is_not_evaluated(self) -> None:
        # Documented trade-off: the template cannot tell what the masked words were, so it does not claim
        # the question is outside the KB even when the rest of it is clearly off-topic.
        env = _env("What does Taro Yamada recommend for ramen in Osaka?")
        assert env["status_kind"] == "not_evaluated", env
        assert env["limitations"] == ["QUERY_TERMS_MASKED"], env
