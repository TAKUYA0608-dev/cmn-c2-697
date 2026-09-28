# CMN-C2-697 — Enterprise AWS AgentCore Deployment Q&A Agent

> **Category**: Cat 2 (domain workflow (a job to be done))
> **Industry**: Common (industry-agnostic)

## Overview

Advisory question-answering for deploying agents on the managed agent runtime named in the title. Given a query with a deployment target, jurisdictions and optional deployment descriptors (id, source system, resource types), the agent routes the question to the matching knowledge-base namespaces, retrieves official references with a lexical scorer, annotates each for applicability, and returns cited answer_sections, code_examples, a least-privilege iam_policy_template built only from actions declared in the retrieved references, a residency lens and a per-deployment provenance trail. Everything is deterministic; no LLM is used, and the agent never executes a deployment or applies a policy. Deployment identifiers are replaced by opaque tokens, a descriptor whose source is not an authorised system of record loses its citation and causes the answer to be held back for a person to check, and a question with no matching reference gets an out-of-scope answer. The reference knowledge base shipped here is a small curated sample — replace it with your own.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | 3.11 or later (`requires-python = ">=3.11"`) |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent raises
`PlatformRequired` during graph compile / start-up preflight rather than starting in a partially
working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Known limitations

**Product names can be masked by the platform before retrieval.** AGENTIC STAR's personal-data
protection runs before this template's code and replaces any run of two or more Title-Case words
with `[MASKED]` — "Amazon Bedrock", "Amazon Bedrock Guardrails" and "Tokyo Region" included — and
the template cannot switch it off. Measured on AgentCore 1.0.3:

| Request | Reaches retrieval as | Result |
|---|---|---|
| `What IAM permissions does our agent need to use Amazon Bedrock Guardrails?` | `…need to use [MASKED]?` | IAM template without `bedrock:ApplyGuardrail`; `confidence: low`, `limitations: ["QUERY_TERMS_MASKED"]` |
| `What IAM permissions does our agent need to use amazon bedrock guardrails?` | unchanged | includes `bedrock:ApplyGuardrail`; confidence medium, `limitations: []` |
| `Explain Amazon Bedrock Guardrails setup.` | `[MASKED] setup.` | `status_kind: not_evaluated`, not `out_of_scope` |
| `How do I tune quantum annealing with Amazon Bedrock Guardrails?` | `How do I tune quantum annealing with [MASKED]?` | `not_evaluated` — the unmasked words matching nothing is not treated as out of scope |
| JSON `deployment_target: "Amazon Bedrock"`, `jurisdictions: ["United States"]` | `[MASKED]`, `[MASKED]` | target not recognised; `confidence: low`, `QUERY_TERMS_MASKED` |
| JSON `deployment_target: "Amazon Bedrock AgentCore"` | `[MASKED] AgentCore` | still recognised as Bedrock AgentCore; not flagged |
| `What does Taro Yamada recommend for ramen in Osaka?` | `What does [MASKED] recommend for ramen in Osaka?` | `not_evaluated` (an off-topic question that contains a masked name is not called out of scope either) |

When part of a request was masked, `limitations` holds the code `QUERY_TERMS_MASKED`, confidence is
never above `low`, and `message` names the masked fields (`query`, `jurisdictions`,
`deployment_target`) and how to rephrase. Write product names in lower case ("bedrock guardrails",
"tokyo region"), or as "Bedrock AgentCore", which is not masked.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/02_design.md` for the design and `docs/03_test_spec.md` for the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
