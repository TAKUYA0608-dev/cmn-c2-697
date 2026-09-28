"""CMN-C2-697 — inner domain workflow graph (Cat 2).

Instantiated by DeploymentAdvisoryWorkflowGraphNode.get_subgraph() in graph.py. Linear topology with per-node
skip guards (the portable Cat 2 form; conditional edges don't propagate across the subgraph boundary):

    START → ingest_scope → knowledge_retrieve → interpret_analyze → answer_synthesize → END

On rejected / 0-hit input, knowledge_retrieve sets retrieval_hit_count=0 (+error_code); interpret_analyze
no-ops and answer_synthesize emits the out-of-scope safe answer — no fabricated deployment advice or IAM
permission.
"""

from __future__ import annotations
from typing import Any

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState

from src.nodes.answer_synthesize_node import AnswerSynthesizeNode
from src.nodes.ingest_scope_node import IngestScopeNode
from src.nodes.interpret_analyze_node import InterpretAnalyzeNode
from src.nodes.knowledge_retrieve_node import KnowledgeRetrieveNode
from src.schemas.state import State


class DeploymentAdvisoryWorkflow(BaseGraph):
    """Inner graph: ingest_scope → knowledge_retrieve → interpret_analyze → answer_synthesize."""

    @property
    def name(self) -> str:
        return "DeploymentAdvisoryWorkflow"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        pass

    def register_nodes(self) -> None:
        # No super() — BaseGraph.register_nodes() is abstract.
        self._nodes["ingest_scope"] = IngestScopeNode()
        self._nodes["knowledge_retrieve"] = KnowledgeRetrieveNode()
        self._nodes["interpret_analyze"] = InterpretAnalyzeNode()
        self._nodes["answer_synthesize"] = AnswerSynthesizeNode()

    def add_edges(self) -> None:
        # Static linear backbone; the 0-hit / rejected skip is handled by per-node guards.
        self._sg.add_edge(START, "ingest_scope")
        self._sg.add_edge("ingest_scope", "knowledge_retrieve")
        self._sg.add_edge("knowledge_retrieve", "interpret_analyze")
        self._sg.add_edge("interpret_analyze", "answer_synthesize")
        self._sg.add_edge("answer_synthesize", END)

    def route(self, state: AgentState) -> str:
        """Required by the BaseGraph ABC. Linear topology → not wired to a conditional edge."""
        if state.get("error_code") or state.get("retrieval_hit_count", 0) == 0:
            return "answer_synthesize"
        return "interpret_analyze"

    def get_output(self, state: AgentState) -> dict[str, Any]:
        return {
            "output": state.get("result"),
            "status": state.get("status"),
            "retrieval_hit_count": state.get("retrieval_hit_count", 0),
            "error_code": state.get("error_code"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
