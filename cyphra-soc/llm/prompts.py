"""The three prompts the SOC sends to the LLM.

A prompt is a frozen dataclass that carries its inputs and renders
itself into a list of :class:`llm.client.Message`. The render is
deterministic — no templates that consult the clock, no templates
that pull from the file system — so a replay against the same
inputs produces the same message list, and the audit chain's
``response.model == response.choices[0].message`` invariant holds
even across process restarts.

The system message is fixed across calls for a given prompt kind;
the user message is the data the prompt is about. The model is
instructed to return JSON, and the parser expects a JSON object —
the three helpers (:func:`parse_hypothesis`,
:func:`parse_narrative`, :func:`parse_disposition`) know the
shape.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from llm.client import Message, Role


# ── prompt dataclasses ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Prompt:
    """The base class for a prompt.

    Subclasses override :meth:`system_message` and :meth:`user_message`
    rather than mutating ``__post_init__``, so a frozen dataclass can
    render itself.
    """

    def system_message(self) -> str:
        raise NotImplementedError

    def user_message(self) -> str:
        raise NotImplementedError

    def render(self) -> list[Message]:
        return [
            Message(role=Role.SYSTEM, content=self.system_message()),
            Message(role=Role.USER, content=self.user_message()),
        ]


@dataclass(frozen=True)
class HypothesisPrompt(Prompt):
    """The hypothesis-generation prompt.

    Given the member findings of an incident, ask the model for the
    next hypothesis to test. The model returns ``{"hypothesis": "...",
    "rationale": "..."}`` — a single new hypothesis plus why it
    follows from what is already known.
    """

    incident_uid: str
    findings: list[dict[str, Any]]
    known_attack: str | None = None

    def system_message(self) -> str:
        return (
            "You are a SOC analyst generating the next investigation "
            "hypothesis for an open incident. Given the member "
            "findings, propose ONE specific hypothesis that would "
            "explain the observed activity and is testable from the "
            "telemetry available. Return a JSON object with two "
            "string fields: hypothesis (the proposed next step) and "
            "rationale (why this follows from the findings). Do not "
            "include any other text."
        )

    def user_message(self) -> str:
        payload: dict[str, Any] = {
            "incident_uid": self.incident_uid,
            "findings": self.findings,
        }
        if self.known_attack is not None:
            payload["known_attack"] = self.known_attack
        return json.dumps(payload, indent=2, default=str)


@dataclass(frozen=True)
class NarrativePrompt(Prompt):
    """The case-narrative prompt.

    Given a case's timeline and current state, render a paragraph
    an analyst can paste into a ticket. Tone is clinical, never
    speculative — the analyst decides what the incident *is*;
    the model decides how to say it.
    """

    case_uid: str
    title: str
    timeline: list[dict[str, Any]]
    severity_id: int

    def system_message(self) -> str:
        return (
            "You are a SOC analyst writing a one-paragraph case "
            "narrative for an external ticket. The paragraph should "
            "be clinical, third-person, and describe only what is in "
            "the timeline — never speculate about intent or outcome. "
            "Return a JSON object with one string field: paragraph. "
            "Do not include any other text."
        )

    def user_message(self) -> str:
        return json.dumps(
            {
                "case_uid": self.case_uid,
                "title": self.title,
                "severity_id": self.severity_id,
                "timeline": self.timeline,
            },
            indent=2,
            default=str,
        )


@dataclass(frozen=True)
class DispositionPrompt(Prompt):
    """The disposition-reasoning prompt.

    Given a finding and the analyst's draft verdict, ask the model
    to surface counter-considerations. The model returns
    ``{"considerations": ["..."]}`` — at most three short strings
    that the analyst should weigh before confirming the disposition.
    The model does not decide the disposition; the analyst does.
    """

    finding_uid: str
    draft_disposition: str
    draft_rationale: str
    context: Mapping[str, Any]

    def system_message(self) -> str:
        return (
            "You are a SOC analyst reviewing a draft disposition "
            "(true_positive, false_positive, or needs_investigation) "
            "before the analyst confirms it. Surface counter-"
            "considerations only — do not propose the disposition "
            "yourself. Return a JSON object with one field: "
            "considerations, a list of at most three short strings "
            "the analyst should weigh. Do not include any other text."
        )

    def user_message(self) -> str:
        return json.dumps(
            {
                "finding_uid": self.finding_uid,
                "draft_disposition": self.draft_disposition,
                "draft_rationale": self.draft_rationale,
                "context": dict(self.context),
            },
            indent=2,
            default=str,
        )


# ── renderers ──────────────────────────────────────────────────────────────


def render(prompt: Prompt) -> list[Message]:
    """Render any :class:`Prompt` to its messages."""
    return prompt.render()


# ── parsers ─────────────────────────────────────────────────────────────────


def _strip_code_fences(text: str) -> str:
    """A model that returns ````json ... ```` is a model that does not
    realise the response is parsed as JSON. Strip the fences before
    trying to load.
    """
    text = text.strip()
    if text.startswith("```"):
        first_nl = text.find("\n")
        if first_nl != -1:
            text = text[first_nl + 1 :]
        if text.endswith("```"):
            text = text[:-3]
    return text.strip()


def parse_hypothesis(response_text: str) -> dict[str, str]:
    """Parse a hypothesis response into ``{hypothesis, rationale}``."""
    doc = json.loads(_strip_code_fences(response_text))
    if not isinstance(doc, Mapping):
        raise ValueError("hypothesis response is not an object")
    return {
        "hypothesis": str(doc.get("hypothesis") or ""),
        "rationale": str(doc.get("rationale") or ""),
    }


def parse_narrative(response_text: str) -> str:
    """Parse a narrative response into the paragraph string."""
    doc = json.loads(_strip_code_fences(response_text))
    if not isinstance(doc, Mapping):
        raise ValueError("narrative response is not an object")
    return str(doc.get("paragraph") or "")


def parse_disposition(response_text: str) -> list[str]:
    """Parse a disposition response into a list of considerations."""
    doc = json.loads(_strip_code_fences(response_text))
    if not isinstance(doc, Mapping):
        raise ValueError("disposition response is not an object")
    items = doc.get("considerations") or []
    if not isinstance(items, list):
        raise ValueError("disposition considerations is not a list")
    return [str(x) for x in items[:3]]


__all__ = [
    "DispositionPrompt",
    "HypothesisPrompt",
    "NarrativePrompt",
    "Prompt",
    "parse_disposition",
    "parse_hypothesis",
    "parse_narrative",
    "render",
]
