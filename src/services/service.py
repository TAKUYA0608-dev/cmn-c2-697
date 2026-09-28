"""CMN-C2-697 — deterministic domain services (no framework imports, no LLM).

DeploymentAdvisoryService: routes an AWS-deployment question into KB namespaces (deploy / iam / bedrock / fisc),
retrieves the relevant AWS-official deployment/ops references from the seeded reference KB (AWS Agent Toolkit /
Amazon Bedrock AgentCore / Bedrock / IAM / FISC) with a deterministic BM25-lite scorer, maps each reference to
the caller deployment context (deployment_target / jurisdictions), and synthesizes an advisory deliverable — a
cited answer + a **least-privilege IAM policy template composed only from KB-declared cited actions** + grounded
code examples + a FISC cloud-residency lens + a per-deployment audit trail.

Everything here is deterministic and auditable (tokenization + keyed KB composition) — there is **no LLM**. The
agent is read-only: it answers deployment *questions* only and never executes a deployment or applies an IAM
policy. A caller deployment descriptor is keyed by an opaque ``dep:<sha8>`` surrogate (the raw name is never
carried into the deliverable), its provenance is resolved to a grounded ``src:<sha8>`` citation only when it
names an authorized deployment/IaC system of record, and the S-3 output gate re-redacts any secret/PII that
leaks. Seeded KB references are overridable by CoE via a change-controlled engineer MR (see docs/07) without
touching node logic.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Two SEPARATE concerns — do not conflate them:
#   (1) PRIVACY (safe_identifier): every caller deployment identifier (deployment_id) is UNCONDITIONALLY
#       tokenized to a deterministic opaque surrogate so PII (even a bare name like ``Alice`` / ``prod-agent`` /
#       ``TaroYamada``, no spaces/symbols) can never reach a citation or the output. Tokenizing is a privacy
#       measure — it does NOT assert the value is authorized/verifiable.
#   (2) PROVENANCE (resolve_provenance): a caller ``source`` becomes a grounded CITATION only when it is
#       resolvable against the authorized deployment/IaC provenance registry (names a trusted system of
#       record). Any other free text (a deployment name, ``unknown``, a fabricated value, or a value merely
#       SHAPED like a surrogate ``src:1a2b3c4d``) is NOT verifiable provenance → it yields NO citation → S-3
#       blocks the per-deployment audit trail as CITATION_INCOMPLETE (fail-closed). "Tokenized" is never
#       sufficient for a citation; the value must first pass provenance validation.
# Tokenization is UNCONDITIONAL (no syntactic passthrough): a caller value merely *shaped* like a surrogate
# (``dep:deadbeef``) is re-hashed, never trusted, so it can never forge an internal join key. Identifiers /
# provenance are resolved exactly once at S-1 (pre_process); downstream trusts that resolution verbatim.

# Authorized provenance registry: the deployment/IaC systems of record an org trusts as verifiable deployment
# provenance sources. A caller ``source`` is accepted as a grounded citation ONLY when its leading namespace
# names one of these (the "trusted context"). This is the deploying org's / CoE's registry — overridable
# without touching node logic; it is a SEMANTIC allowlist of authorized systems, not a syntactic character
# class.
AUTHORIZED_PROVENANCE_SYSTEMS = frozenset(
    {
        "cloudformation",
        "cfn",
        "stack",
        "cloudformation_stack",
        "terraform",
        "terraform_cloud",
        "terraform_state",
        "tfstate",
        "tfc",
        "cdk",
        "aws_cdk",
        "sam",
        "serverless",
        "aws_config",
        "config",
        "config_aggregator",
        "service_catalog",
        "servicecatalog",
        "systems_manager",
        "ssm",
        "parameter_store",
        "codepipeline",
        "code_pipeline",
        "deployment_pipeline",
        "pipeline",
        "codedeploy",
        "control_tower",
        "organizations",
        "aws_organizations",
        "iam_access_analyzer",
        "access_analyzer",
        "cloudtrail",
        "audit_log",
        "ecr",
        "image_registry",
        "artifact_registry",
        "gitops",
        "argocd",
        "flux",
        "deployment_registry",
    }
)


def _sha8(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def safe_identifier(value: Any) -> str:
    """PRIVACY tokenize a caller deployment identifier to a deterministic opaque surrogate ``dep:<sha8>``.

    Caller identifiers are **always** tokenized — no syntactic passthrough — so a name (with or without
    spaces) can never survive into a citation or the output, and a caller value merely *shaped* like a
    surrogate (``dep:deadbeef``) is re-hashed rather than trusted (it can never forge an internal join key).
    Same input → same surrogate (answer sections / audit trail stay joinable within one invocation). This is a
    privacy measure only; it makes no claim that the identifier is authorized.
    """
    return "dep:" + _sha8(str(value or "").strip())


def resolve_provenance(value: Any) -> str | None:
    """Resolve a **raw** caller ``source`` to a grounded, privacy-tokenized CITATION — or ``None``.

    Provenance validation (separate from privacy) and the **single** resolution point (S-1 / pre_process).
    A citation is emitted **only** when the source names an authorized deployment/IaC system of record
    (``<authorized-namespace>[:<ref>]``). Any other value — a deployment name, ``unknown``, a fabricated value,
    **or a value that merely looks like a surrogate (``src:1a2b3c4d``)** — is not verifiable provenance and
    returns ``None`` so the S-3 gate blocks the per-deployment audit trail as CITATION_INCOMPLETE (fail-closed).
    When authorized, the raw label is never used verbatim: the citation is a privacy hash (``src:<sha8>``) of
    the authorized reference. No synthetic provenance is fabricated.

    ★ Forged-surrogate defence: there is **no format-based passthrough**. A caller-supplied ``src:<hex>``
    has namespace ``src``, which is not an authorized system of record, so it resolves to ``None`` — it is
    dropped here at S-1 and can never reach a citation. Because provenance is resolved exactly once (here),
    the produced ``src:<sha8>`` is the trusted citation downstream and is **never** fed back through this
    function (which would, correctly, reject it), so no forged value can imitate an internal surrogate.
    """
    text = str(value or "").strip()
    if not text:
        return None
    namespace = text.split(":", 1)[0].strip().lower()
    if namespace not in AUTHORIZED_PROVENANCE_SYSTEMS:
        return None  # unverifiable / forged-surrogate provenance → fail-closed (no citation → needs_review)
    return "src:" + _sha8(text)


# ── seeded deployment KB (AWS-official deployment/ops references) ──────────────────────────────────────────
# Each reference: {doc_id, namespace, source, article, citation_label, title, guidance, recommended_steps[],
#                  iam_actions[], code_example{language,snippet}|None, fisc_note|None, jurisdiction, keywords[],
#                  applies_to[]}. `citation_label` is the human-readable source+article; the grounded surrogate
# is a KB-owned `stat:<sha8>` (never caller-supplied). `iam_actions` seeds the least-privilege IAM template.
DEPLOYMENT_KB: list[dict[str, Any]] = [
    {
        "doc_id": "agentcore-runtime-deploy",
        "namespace": "deploy",
        "source": "Amazon Bedrock AgentCore",
        "article": "Runtime — Deploy an agent",
        "citation_label": "Amazon Bedrock AgentCore Developer Guide — Runtime: deploy an agent",
        "title": "Deploy an agent to Bedrock AgentCore Runtime",
        "guidance": "Package the agent as a container image, push it to Amazon ECR, register an AgentCore "
        "Runtime with an execution role, and invoke it through the AgentCore endpoint.",
        "recommended_steps": [
            "Build the agent container image and push it to Amazon ECR.",
            "Create an AgentCore Runtime referencing the image and an execution role.",
            "Attach a least-privilege execution role (see the IAM references).",
            "Invoke the runtime endpoint and validate the response envelope.",
        ],
        "iam_actions": [
            "bedrock-agentcore:CreateAgentRuntime",
            "bedrock-agentcore:InvokeAgentRuntime",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
        ],
        "code_example": {
            "language": "bash",
            "snippet": "aws bedrock-agentcore create-agent-runtime \\\n"
            "  --agent-runtime-name my-agent \\\n"
            "  --container-uri <account>.dkr.ecr.<region>.amazonaws.com/my-agent:latest \\\n"
            "  --role-arn arn:aws:iam::<account>:role/my-agent-exec",
        },
        "fisc_note": None,
        "jurisdiction": "ANY",
        "keywords": [
            "deploy",
            "deployment",
            "agentcore",
            "runtime",
            "container",
            "ecr",
            "endpoint",
            "host",
            "package",
            "image",
            "invoke",
            "publish",
            "ship",
            "release",
            "how to deploy",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
    {
        "doc_id": "agent-toolkit-getting-started",
        "namespace": "deploy",
        "source": "AWS Agent Toolkit (aws/agent-toolkit-for-aws)",
        "article": "Getting Started",
        "citation_label": "AWS Agent Toolkit for AWS — Getting Started / project scaffolding",
        "title": "Scaffold and deploy with the AWS Agent Toolkit",
        "guidance": "Use the AWS Agent Toolkit CLI to scaffold an agent project, configure the target (Bedrock "
        "AgentCore), and drive the build/deploy from a single toolkit workflow.",
        "recommended_steps": [
            "Install the AWS Agent Toolkit CLI and initialize a project.",
            "Configure the deployment target and model in the toolkit config.",
            "Run the toolkit build/deploy workflow.",
        ],
        "iam_actions": [],
        "code_example": {
            "language": "bash",
            "snippet": "agent-toolkit init my-agent\n" "agent-toolkit deploy --target bedrock-agentcore",
        },
        "fisc_note": None,
        "jurisdiction": "ANY",
        "keywords": [
            "agent toolkit",
            "toolkit",
            "cli",
            "scaffold",
            "starter",
            "getting started",
            "init",
            "project",
            "aws",
            "template",
            "boilerplate",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
    {
        "doc_id": "iam-least-privilege-runtime",
        "namespace": "iam",
        "source": "AWS IAM",
        "article": "Least-Privilege Execution Role",
        "citation_label": "AWS IAM User Guide — grant least privilege (execution role for an agent runtime)",
        "title": "Least-privilege execution role for an AgentCore runtime",
        "guidance": "Grant only the runtime-invoke, model-invoke, and logging actions the agent needs; scope "
        'each statement to a specific resource ARN and never use a `"*"` resource wildcard.',
        "recommended_steps": [
            "Enumerate the actions the agent actually calls at runtime.",
            "Group them into per-service statements scoped to specific resource ARNs.",
            "Deny wildcards; validate with IAM Access Analyzer before applying.",
        ],
        "iam_actions": [
            "bedrock:InvokeModel",
            "bedrock-agentcore:InvokeAgentRuntime",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "code_example": None,
        "fisc_note": None,
        "jurisdiction": "ANY",
        "keywords": [
            "iam",
            "permission",
            "permissions",
            "least privilege",
            "least-privilege",
            "role",
            "policy",
            "execution role",
            "privilege",
            "access",
            "grant",
            "principal",
            "scope",
            "over-privileged",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
    {
        "doc_id": "iam-bedrock-model-access",
        "namespace": "iam",
        "source": "Amazon Bedrock",
        "article": "Model Access IAM",
        "citation_label": "Amazon Bedrock User Guide — IAM permissions for model invocation",
        "title": "IAM for Bedrock model invocation",
        "guidance": "To invoke a foundation model, the execution role needs the Bedrock model-invoke actions "
        "scoped to the specific model ARN(s) the agent uses.",
        "recommended_steps": [
            "Identify the foundation model ARNs the agent invokes.",
            "Grant the model-invoke actions scoped to those ARNs only.",
        ],
        "iam_actions": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:ListFoundationModels"],
        "code_example": None,
        "fisc_note": None,
        "jurisdiction": "ANY",
        "keywords": [
            "bedrock",
            "model",
            "invoke",
            "invokemodel",
            "foundation model",
            "iam",
            "model access",
            "permission",
            "inference",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
    {
        "doc_id": "bedrock-agentcore-memory-gateway",
        "namespace": "bedrock",
        "source": "Amazon Bedrock AgentCore",
        "article": "Memory & Gateway",
        "citation_label": "Amazon Bedrock AgentCore Developer Guide — Memory & Gateway configuration",
        "title": "Configure AgentCore Memory and Gateway",
        "guidance": "Use AgentCore Memory for session/long-term state and AgentCore Gateway to expose tools "
        "(including MCP) to the agent runtime.",
        "recommended_steps": [
            "Create an AgentCore Memory resource and bind it to the runtime.",
            "Register tools/MCP endpoints through AgentCore Gateway.",
        ],
        "iam_actions": ["bedrock-agentcore:CreateMemory", "bedrock-agentcore:GetMemory"],
        "code_example": None,
        "fisc_note": None,
        "jurisdiction": "ANY",
        "keywords": [
            "bedrock",
            "agentcore",
            "memory",
            "gateway",
            "session",
            "tool",
            "tools",
            "mcp",
            "state",
            "long-term",
            "context",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
    {
        "doc_id": "bedrock-guardrails",
        "namespace": "bedrock",
        "source": "Amazon Bedrock",
        "article": "Guardrails",
        "citation_label": "Amazon Bedrock User Guide — Guardrails for content filtering",
        "title": "Apply Bedrock Guardrails to the agent",
        "guidance": "Attach a Bedrock Guardrail to filter content, block denied topics, and redact sensitive "
        "information on the agent's model calls.",
        "recommended_steps": [
            "Create a Bedrock Guardrail with the content/topic policies you require.",
            "Reference the guardrail on the model-invoke calls.",
        ],
        "iam_actions": ["bedrock:ApplyGuardrail"],
        "code_example": None,
        "fisc_note": None,
        "jurisdiction": "ANY",
        "keywords": [
            "guardrail",
            "guardrails",
            "safety",
            "filter",
            "bedrock",
            "content",
            "redact",
            "block",
            "denied topics",
            "moderation",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
    {
        "doc_id": "fisc-cloud-residency",
        "namespace": "fisc",
        "source": "FISC Security Guidelines",
        "article": "FY2026 Cloud Residency",
        "citation_label": "FISC 金融機関等コンピュータシステムの安全対策基準 (FY2026) — cloud data residency",
        "title": "FISC cloud-residency documentation for financial-sector agents",
        "guidance": "For financial / insurance workloads, deploy in an approved Japan Region, document data "
        "residency, enable KMS encryption at rest and in transit, and retain CloudTrail audit logs "
        "per the FISC guidelines.",
        "recommended_steps": [
            "Deploy in an approved JP Region (e.g. ap-northeast-1 / ap-northeast-3).",
            "Document the data-residency boundary and KMS encryption configuration.",
            "Enable CloudTrail audit logging and retain the residency evidence.",
        ],
        "iam_actions": ["kms:Encrypt", "kms:Decrypt", "cloudtrail:LookupEvents"],
        "code_example": None,
        "fisc_note": "Deploy in an approved JP Region (e.g. ap-northeast-1 / ap-northeast-3); document data "
        "residency, KMS encryption at rest/in transit, and CloudTrail audit retention.",
        "jurisdiction": "JP",
        "keywords": [
            "fisc",
            "residency",
            "region",
            "financial",
            "insurance",
            "compliance",
            "data residency",
            "japan",
            "jp",
            "kms",
            "encryption",
            "audit",
            "sovereignty",
            "地域",
            "所在",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
    {
        "doc_id": "deploy-observability",
        "namespace": "deploy",
        "source": "AWS Observability",
        "article": "Agent Tracing & Logs",
        "citation_label": "AWS Observability — CloudWatch Logs / X-Ray tracing for a deployed agent",
        "title": "Observability for a deployed agent (CloudWatch / X-Ray)",
        "guidance": "Emit structured logs to CloudWatch, publish custom metrics, and enable X-Ray tracing so a "
        "deployed agent's invocations are observable and debuggable.",
        "recommended_steps": [
            "Emit structured logs and custom metrics from the agent runtime.",
            "Enable X-Ray tracing and correlate traces with invocation ids.",
        ],
        "iam_actions": ["logs:PutLogEvents", "xray:PutTraceSegments", "cloudwatch:PutMetricData"],
        "code_example": None,
        "fisc_note": None,
        "jurisdiction": "ANY",
        "keywords": [
            "observability",
            "monitoring",
            "cloudwatch",
            "logs",
            "logging",
            "tracing",
            "x-ray",
            "xray",
            "metrics",
            "trace",
            "debug",
            "telemetry",
        ],
        "applies_to": ["bedrock_agentcore", "any"],
    },
]

# namespace router: which KB namespace(s) a query is about (deterministic keyword routing)
_NAMESPACE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "deploy": (
        "deploy",
        "deployment",
        "runtime",
        "container",
        "ecr",
        "endpoint",
        "host",
        "package",
        "ship",
        "release",
        "publish",
        "toolkit",
        "scaffold",
        "observability",
        "monitoring",
        "cloudwatch",
        "logs",
        "tracing",
    ),
    "iam": (
        "iam",
        "permission",
        "permissions",
        "role",
        "policy",
        "least privilege",
        "least-privilege",
        "privilege",
        "access",
        "grant",
        "principal",
    ),
    "bedrock": (
        "bedrock",
        "model",
        "invoke",
        "foundation model",
        "guardrail",
        "guardrails",
        "memory",
        "gateway",
        "mcp",
    ),
    "fisc": (
        "fisc",
        "residency",
        "financial",
        "insurance",
        "region",
        "data residency",
        "sovereignty",
        "kms",
        "encryption",
    ),
}

# deployment-target hint tokens → canonical target code
_TARGET_ALIASES = {
    "bedrock agentcore": "bedrock_agentcore",
    "agentcore": "bedrock_agentcore",
    "bedrock": "bedrock_agentcore",
    "agentcore runtime": "bedrock_agentcore",
}
# jurisdiction hint tokens → canonical jurisdiction code
_JURISDICTION_ALIASES = {
    "jp": "JP",
    "japan": "JP",
    "japanese": "JP",
    "fisc": "JP",
    "日本": "JP",
    "us": "US",
    "usa": "US",
    "united states": "US",
    "eu": "EU",
    "europe": "EU",
    "european": "EU",
}

_TOKEN = re.compile(r"[a-z0-9]+|[ぁ-んァ-ヶ一-龠]+")
_STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "of",
        "to",
        "for",
        "and",
        "or",
        "in",
        "on",
        "we",
        "our",
        "is",
        "are",
        "what",
        "which",
        "how",
        "do",
        "does",
        "under",
        "with",
        "this",
        "that",
        "when",
        "using",
        "use",
        "used",
        "need",
        "should",
    }
)


def _tokenize(text: str) -> list[str]:
    """Lowercase word/kana/kanji tokens, stopwords removed (deterministic, no LLM)."""
    return [t for t in _TOKEN.findall((text or "").lower()) if t not in _STOPWORDS and len(t) > 1]


# The platform's S-2 personal-data pass runs before any template code and replaces anything its person-name
# heuristic matches (a run of two or more Title-Case words, e.g. "Amazon Bedrock", "Amazon Bedrock Guardrails",
# "Tokyo Region", "United States") with this token. The template cannot switch that pass off (the input gate is
# final). References that only the masked words would have matched cannot be retrieved, so a masked request is
# reported with a limitation code instead of as a complete answer.
PLATFORM_MASK_TOKEN = "[MASKED]"
# Stable machine-readable limitation code (the human-readable explanation goes in the envelope `message`).
QUERY_TERMS_MASKED = "QUERY_TERMS_MASKED"


def masked_request_fields(query: str, jurisdictions: list[str], target: Any, target_code: str | None) -> list[str]:
    """Names of the request fields that drive routing / retrieval / applicability and reached the agent masked.

    `query` drives namespace routing and retrieval, `jurisdictions` the FISC residency applicability,
    `deployment_target` the per-reference applicability. A masked `deployment_target` that still normalised
    (e.g. "[MASKED] AgentCore" → bedrock_agentcore) lost nothing and is not listed. Deployment descriptors are
    not read by retrieval (they are echoed in the audit trail, where a masked value stays visible).
    """
    fields: list[str] = []
    if PLATFORM_MASK_TOKEN in (query or ""):
        fields.append("query")
    if any(PLATFORM_MASK_TOKEN in str(j) for j in jurisdictions or []):
        fields.append("jurisdictions")
    if PLATFORM_MASK_TOKEN in str(target or "") and target_code is None:
        fields.append("deployment_target")
    return fields


class DeploymentAdvisoryService:
    """Deterministic namespace routing, BM25-lite retrieval, mapping, IAM/synthesis composition."""

    # ── namespace routing ─────────────────────────────────────────────────────
    @staticmethod
    def route_namespaces(query: str) -> list[str]:
        """Route a query to KB namespace(s) (deterministic keyword match). [] when nothing matches."""
        low = (query or "").lower()
        tokens = set(_tokenize(query))
        namespaces: set[str] = set()
        for ns, kws in _NAMESPACE_KEYWORDS.items():
            for kw in kws:
                if " " in kw:
                    if kw in low:
                        namespaces.add(ns)
                        break
                elif kw in tokens:
                    namespaces.add(ns)
                    break
        return sorted(namespaces)

    @staticmethod
    def normalize_target(value: Any) -> str | None:
        low = str(value or "").strip().lower()
        if not low:
            return None
        for token, code in _TARGET_ALIASES.items():
            if token in low:
                return code
        return None

    @staticmethod
    def classify_jurisdictions(query: str, jurisdictions: list[str] | None) -> list[str]:
        """Classify a query + explicit jurisdictions into jurisdiction codes (deterministic keyword match)."""
        low = (query or "").lower()
        tokens = set(_tokenize(query))
        codes: set[str] = set()
        code: str | None
        for token, code in _JURISDICTION_ALIASES.items():
            if " " in token:
                if token in low:
                    codes.add(code)
            elif token in tokens:
                codes.add(code)
        for j in jurisdictions or []:
            code = _JURISDICTION_ALIASES.get(str(j).strip().lower())
            if code:
                codes.add(code)
        return sorted(codes)

    # ── BM25-lite retrieval ────────────────────────────────────────────────────
    @staticmethod
    def retrieve(query: str, namespaces: list[str], top_k: int = 8) -> list[dict[str, Any]]:
        """Keyword-scored retrieval over the deployment KB. [] when nothing matches (out-of-scope).

        Score = (matched reference keywords, each weighted) + routed-namespace boost. Deterministic and
        auditable — no vector model, no LLM. Ties break on doc_id for a stable order.
        """
        q_tokens = set(_tokenize(query))
        q_low = (query or "").lower()
        scored: list[tuple[int, dict[str, Any]]] = []
        for rec in DEPLOYMENT_KB:
            score = 0
            for kw in rec["keywords"]:
                kw_low = kw.lower()
                if " " in kw_low:
                    if kw_low in q_low:
                        score += 3  # multi-word phrase match is a strong signal
                elif kw_low in q_tokens:
                    score += 2
            if score and namespaces and rec["namespace"] in namespaces:
                score += 2  # routed-namespace relevance boost (only when the reference already matched)
            if score:
                scored.append((score, rec))
        scored.sort(key=lambda x: (-x[0], x[1]["doc_id"]))
        out: list[dict[str, Any]] = []
        for score, rec in scored[:top_k]:
            out.append(
                {
                    "doc_id": rec["doc_id"],
                    "namespace": rec["namespace"],
                    "source": rec["source"],
                    "article": rec["article"],
                    "citation_label": rec["citation_label"],
                    "title": rec["title"],
                    "guidance": rec["guidance"],
                    "recommended_steps": rec["recommended_steps"],
                    "iam_actions": rec["iam_actions"],
                    "code_example": rec["code_example"],
                    "fisc_note": rec["fisc_note"],
                    "jurisdiction": rec["jurisdiction"],
                    "applies_to": rec["applies_to"],
                    "score": score,
                    # KB-owned grounded citation surrogate (never caller-supplied)
                    "citation": "stat:" + _sha8(rec["doc_id"] + "|" + rec["citation_label"]),
                }
            )
        return out

    # ── reference → context mapping ─────────────────────────────────────────────
    @staticmethod
    def map_reference(ref: dict[str, Any], target: str | None, jurisdictions: list[str]) -> dict[str, Any]:
        """Annotate a retrieved reference with its applicability to the caller deployment context."""
        applies_to = set(ref.get("applies_to", []))
        target_applies = (target is None) or (target in applies_to) or ("any" in applies_to)
        jurisdiction_applies = (
            (ref["jurisdiction"] == "ANY") or (not jurisdictions) or (ref["jurisdiction"] in jurisdictions)
        )
        reasons: list[str] = []
        if target and target in applies_to:
            reasons.append(f"applies to deployment target '{target}'")
        if jurisdictions and ref["jurisdiction"] in jurisdictions:
            reasons.append(f"in scope for jurisdiction {ref['jurisdiction']}")
        if not reasons:
            reasons.append("general deployment guidance")
        return {
            "doc_id": ref["doc_id"],
            "applies": bool(target_applies and jurisdiction_applies),
            "applicability": "; ".join(reasons),
        }

    # ── least-privilege IAM template (KB-declared cited actions only — anti-hallucination) ──────────
    @staticmethod
    def build_iam_policy_template(refs: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Compose a least-privilege IAM policy template from the KB-declared, cited actions of the retrieved
        references. Every action is grounded in a cited reference (never fabricated); no `Resource: "*"` is
        emitted — a `REPLACE_WITH_SPECIFIC_RESOURCE_ARN` placeholder enforces least-privilege scoping."""
        statements: list[dict[str, Any]] = []
        for ref in refs:
            actions = ref.get("iam_actions") or []
            if not actions:
                continue
            statements.append(
                {
                    "Sid": re.sub(r"[^A-Za-z0-9]", "", ref["doc_id"].title()),
                    "Effect": "Allow",
                    "Action": sorted(set(actions)),
                    "Resource": ["REPLACE_WITH_SPECIFIC_RESOURCE_ARN"],  # least-privilege: never "*"
                    "_citation": ref["citation"],  # grounded — the KB reference this action set came from
                    "_source": ref["citation_label"],
                }
            )
        if not statements:
            return None
        return {
            "Version": "2012-10-17",
            "Statement": statements,
            "_least_privilege_note": (
                "DRAFT least-privilege policy. Each action is grounded in a cited AWS-official reference; "
                'replace every Resource with the specific ARN (do not use "*"). Verify before applying.'
            ),
        }

    @staticmethod
    def collect_code_examples(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Collect grounded code examples from the retrieved references (each cited to its source)."""
        examples: list[dict[str, Any]] = []
        for ref in refs:
            ex = ref.get("code_example")
            if not ex:
                continue
            examples.append(
                {
                    "doc_id": ref["doc_id"],
                    "language": ex.get("language", "text"),
                    "snippet": ex.get("snippet", ""),
                    "citation": ref["citation"],
                }
            )
        return examples

    # ── deployment audit trail ───────────────────────────────────────────────────
    @staticmethod
    def build_deployment_audit_trail(deployments: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build the per-deployment audit trail. Each deployment's provenance was resolved once at S-1
        (pre_process) to a grounded ``src:<sha8>`` citation or ``None`` (unverifiable / forged surrogate
        dropped). Trust that value verbatim; never re-resolve or fabricate. A ``None`` provenance → the item
        carries no citation → S-3 blocks the trail as CITATION_INCOMPLETE (fail-closed)."""
        trail: list[dict[str, Any]] = []
        for d in deployments or []:
            if not isinstance(d, dict):
                continue
            # Tokenize unconditionally (no forgeable passthrough). pre_process (S-1) already tokenized the
            # deployment_id to an opaque surrogate; re-tokenizing here is a deterministic label-only op (the
            # surrogate is a per-invocation label joined only within this output — never a forgeable key), so
            # re-hashing an already-opaque value is harmless.
            deployment_id = safe_identifier(d.get("deployment_id") or d.get("agent_id") or d.get("id") or "")
            provenance = d.get("source")  # already resolved (src:<sha8> or None) at S-1
            resource_types = [str(t) for t in d.get("resource_types", []) if isinstance(t, (str, int))]
            trail.append(
                {
                    "deployment_id": deployment_id,
                    "resource_types": resource_types,
                    "provenance": provenance,
                    "provenance_status": "documented" if provenance else "unverified",
                    # grounded provenance citation only when resolved; None → S-3 fail-closed
                    "citation": provenance,
                }
            )
        return trail

    # ── deliverable synthesis ────────────────────────────────────────────────────
    @staticmethod
    def synthesize(
        query_namespaces: list[str],
        target: str | None,
        refs: list[dict[str, Any]],
        analyzed: list[dict[str, Any]],
        audit_trail: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Assemble the deployment-advisory deliverable (answer + IAM template + code + FISC + audit trail)."""
        applic_by_id = {m["doc_id"]: m for m in analyzed}
        answer_sections: list[dict[str, Any]] = []
        seen_cite: set[str] = set()
        citations: list[dict[str, str]] = []
        fisc_section: dict[str, Any] | None = None
        for ref in refs:
            m = applic_by_id.get(ref["doc_id"], {})
            answer_sections.append(
                {
                    "doc_id": ref["doc_id"],
                    "namespace": ref["namespace"],
                    "source": ref["source"],
                    "article": ref["article"],
                    "title": ref["title"],
                    "guidance": ref["guidance"],
                    "recommended_steps": ref["recommended_steps"],
                    "applicability": m.get("applicability", "general deployment guidance"),
                    "applies": m.get("applies", True),
                    "citation": ref["citation"],
                    "citation_label": ref["citation_label"],
                }
            )
            if ref["citation"] not in seen_cite:
                seen_cite.add(ref["citation"])
                citations.append(
                    {
                        "source": ref["source"],
                        "article": ref["article"],
                        "citation": ref["citation"],
                        "citation_label": ref["citation_label"],
                    }
                )
            if ref["namespace"] == "fisc" and fisc_section is None:
                fisc_section = {
                    "applicable": True,
                    "note": ref["fisc_note"],
                    "citation": ref["citation"],
                    "citation_label": ref["citation_label"],
                }
        iam_policy_template = DeploymentAdvisoryService.build_iam_policy_template(refs)
        code_examples = DeploymentAdvisoryService.collect_code_examples(refs)
        sources = sorted({ref["source"] for ref in refs})
        return {
            "status_kind": "deployment_advisory",
            "query_namespaces": query_namespaces,
            "deployment_target": target,
            "sources_covered": sources,
            "answer_sections": answer_sections,
            "iam_policy_template": iam_policy_template,
            "code_examples": code_examples,
            "fisc_residency": fisc_section,
            "deployment_audit_trail": audit_trail,
            "citations": citations,
            "confidence": "medium" if answer_sections else "low",
            "message": (
                "参考: 以下は本問い合わせに該当する AWS 公式デプロイ/運用リファレンスに基づく DRAFT の"
                "デプロイ助言です。IAM 権限付与・リージョン所在(FISC)対応・本番デプロイの可否は"
                "認可されたクラウド/セキュリティ担当者にご確認ください(verify before applying)。"
            ),
        }
