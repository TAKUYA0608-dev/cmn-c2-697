# CMN-C2-697 — Integration: pre → inner workflow (linear) → post, and the real outer invoke path

import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph
from src.nodes.answer_synthesize_node import AnswerSynthesizeNode
from src.nodes.ingest_scope_node import IngestScopeNode
from src.nodes.interpret_analyze_node import InterpretAnalyzeNode
from src.nodes.knowledge_retrieve_node import KnowledgeRetrieveNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode

_SUCCESS = AgentStatus.SUCCESS.value

_REQUEST = {
    "query": ("We are deploying an enterprise RAG agent to Bedrock AgentCore Runtime. What are the deployment "
              "steps, the least-privilege IAM role for invoking the Bedrock model, and the FISC cloud-residency "
              "requirements for a financial-sector workload in Japan?"),
    "deployment_target": "Bedrock AgentCore",
    "jurisdictions": ["JP"],
    "deployments": [
        {"deployment_id": "prod-agent-runtime", "source": "cloudformation:agent-stack",
         "resource_types": ["agent_runtime", "iam_role"]},
    ],
}


def _run(user_input: str) -> dict:
    state: dict = {"user_input": user_input, "input_context": {"channel": "deployment_console"},
                   "node_history": [], "error_log": []}
    state.update(PreProcessNode().execute(state) or {})
    for node in (IngestScopeNode(), KnowledgeRetrieveNode(), InterpretAnalyzeNode(), AnswerSynthesizeNode()):
        state.update(node.execute(state) or {})
    state.update(PostProcessNode().execute(state) or {})
    return state


class TestEndToEnd:
    def test_grounded_answer_with_citations(self):
        state = _run(json.dumps(_REQUEST, ensure_ascii=False))
        assert state["status"] == _SUCCESS
        assert state["audit_logged"] is True
        env = json.loads(state["formatted_output"])
        assert env["status_kind"] == "deployment_advisory"
        assert env["answer_sections"] and env["citations"]
        assert env["iam_policy_template"] is not None
        assert env["deployment_audit_trail"][0]["provenance_status"] == "documented"
        assert "DRAFT" in env["disclaimer"] or "参考" in env["disclaimer"]

    def test_multiple_sources_and_fisc_lens(self):
        env = json.loads(_run(json.dumps(_REQUEST, ensure_ascii=False))["formatted_output"])
        assert len(env["sources_covered"]) >= 2
        assert env["fisc_residency"] is not None  # FISC routed for a JP financial workload

    def test_out_of_scope_safe(self):
        env = json.loads(_run("recommend a good ramen shop in Osaka")["formatted_output"])
        assert env["status_kind"] == "out_of_scope"
        assert env["citations"] == []
        assert env["iam_policy_template"] is None
        assert "DRAFT" in env["disclaimer"] or "参考" in env["disclaimer"]

    def test_empty_degrades_but_audits(self):
        state = _run("   ")
        assert state["status"] == _SUCCESS
        assert state["audit_logged"] is True
        assert json.loads(state["formatted_output"])["status_kind"] == "out_of_scope"

    def test_deployment_name_never_in_output(self):
        req = dict(_REQUEST)
        req["deployments"] = [{"deployment_id": "山田太郎の本番エージェント", "source": "terraform:state-9"}]
        state = _run(json.dumps(req, ensure_ascii=False))
        assert "山田太郎" not in state["formatted_output"]
        assert "山田太郎" not in state["validated_input"]

    def test_real_invoke_end_to_end(self):
        ctx = InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
        out = Graph().invoke(json.dumps(_REQUEST, ensure_ascii=False), ctx=ctx)
        assert out["status"] == _SUCCESS
        assert "PostProcessNode" in out["node_history"]
        env = json.loads(out["output"])
        assert env["status_kind"] == "deployment_advisory"
        assert env["answer_sections"] and env["citations"]
