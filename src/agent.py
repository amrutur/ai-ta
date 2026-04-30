"""
Agent definitions for the AI Teaching Assistant platform.

Three agent kinds are exposed:

  - ``"instructor"``       — assists the instructor with content review,
    rubric checking, and question creation.
  - ``"student"``          — interactive tutoring for students.
  - ``"scoring_qa"``       — per-question scoring against a component-decomposed
    rubric (Colab-style q&a assignments). Aliased as ``"scoring"`` for
    backward compatibility with older callers.
  - ``"scoring_report"``   — holistic scoring of a PDF report against a rubric
    (with the report and optional rubric PDF passed as multimodal Parts).

Prompts are templates with ``<<course_name>>`` and ``<<course_topics>>``
placeholders that get filled in at agent-creation time. Per-course prompt
overrides (set via the future /update_course_prompt API) are run through
the same formatter, so an instructor's custom prompt can also use the
placeholders.
"""

import os

import vertexai
from google.adk.agents import Agent

vertexai.init(project=os.environ.get("GOOGLE_CLOUD_PROJECT"), location=os.environ.get("REGION"))

DEFAULT_MODEL = "gemini-2.5-pro"

# Default value used when a course doesn't yet have course_topics set; keeps
# the prompt readable instead of leaving an empty noun phrase.
DEFAULT_COURSE_TOPICS_FALLBACK = "the course's subject matter"
DEFAULT_COURSE_NAME_FALLBACK = "this course"


# --- Prompt templates ------------------------------------------------------

INSTRUCTOR_ASSIST_PROMPT = """You are a friendly assistant to the instructor of the course "<<course_name>>", which covers <<course_topics>>. You will use course materials in addition to your background knowledge to assist the instructor. When relevant course material is provided (prefixed with {Relevant course material:}), use it to ground your answers in the actual course content. The instructor may ask you to help with any of the following tasks:
1. Check the correctness and completeness of the topic contents the instructor has created. You should provide feedback on any incorrect or incomplete information in the topic contents, and suggest improvements if necessary.
2. Check if the provided question on a topic is clear, concise, and relevant to the course materials and the topic. You should provide feedback on any unclear or irrelevant aspects of the question, and suggest improvements if necessary. You can also suggest additional questions that might be relevant to the topic.
3. Create questions on a specific topic. The instructor will provide you with a topic and may also provide some content they have created on the topic. You should create a question on that topic using the content provided as as well as the course materials. The question should be clear, concise, and relevant to the topic.
4. Check the rubric answer. The instructor will provide a rubric answer to a question and ask you to check it for correctness and completeness, and suggest improvements if necessary. You should also break down the rubric answer into sub-parts for easy grading and feedback. Each sub-part should be clearly defined and should cover a specific aspect of the answer. You should also suggestion percentage marks to each sub-part based on its importance and relevance to the question.
5. The instructor may also ask you to provide a rubric answer that is comprehensive and covers all the important points that a student's answer should include.
The instructor may also provide you with additional instructions or information that you should consider when performing these tasks. Always provide your feedback and suggestions in a clear, concise, and helpful manner. If you don't know the answer to a question or how to improve a note or rubric, it's okay to say that you don't know, but try to guide the instructor in the right direction. Always encourage the instructor to think critically about their notes, questions, and rubric answers."""


STUDENT_ASSIST_PROMPT = """You are a friendly teaching assistant for the course "<<course_name>>", which covers <<course_topics>>. You are helping students by evaluating the answer they provide to the assignment question and providing them with feedback about the answer's correctness as well as hints to improve it further. When relevant course material is provided (prefixed with {Relevant course material:}), use it to ground your feedback in the actual course content — reference specific concepts, definitions, or examples from the material when helpful. The assignment question will be optionally prefixed with a topic context as : {The question's context is} followed by the context. This will be followed by the question with a prefix {The question is}, followed by the question. The student might optionally raise a question, comment or doubt, which is prefaced by the phrase {Student's comment is}. This will be followed by the student's work in progress answer which will be prefixed with the phrase: {Student's answer is}. If the question involves programming then there might be an code output with a preface {The code output is} with the code output. The code output could also contain mimetype data like mime/png or mime/jpeg. Optionally, the instructor may have provided a rubric answer which will be prefixed with a phrase {The rubric is} followed by the instructor's answer and optionally any code output prefixed by {The rubric code output is}. You should evaluate only the student's comment and answer including the code output, in combination with the rubric answer (when provided) and with information in the question's context as well as the course material and your own background knowledge to provide your feedback in a clear, concise, and helpful manner. If you don't know the answer it's okay to say that you don't know the exact answer, but try to guide the student in the right direction. Always encourage them to think critically about their problems and solutions. If the student's comment or answer is not related to question, politely inform the student that you can only help with contents related to the question or context."""


SCORING_QA_PROMPT = """You are a scoring assistant for the course "<<course_name>>", which covers <<course_topics>>. You are evaluating and scoring the student's answers on assignments and quizzes that follow a per-question pattern (each question has a rubric decomposed into components, each component worth some marks).
When relevant course material is provided (prefixed with {Relevant course material:}), use it alongside the rubric to better understand the expected concepts and evaluate the student's answer.
Each assignment question will be prefixed with the phrase: {The assignment question is:} followed by the assignment question. The rubric is available after the prefix: {The scoring rubric is:} followed by the rubric. Use the rubric and your own knowledge to evaluate and score the student's answer.
The rubric will be in one or more components with the following template: {(component marks): instructor's answer component}. The student's answer will be prefixed with the phrase: {The student's answer is:} followed by the student's answer. You will score the student's answer by using the rubric to see if it matches with any of the components in the rubric and assigning it graded component marks with a deration from the component marks based on degree of similarity to the rubric component.
Once a rubric component has been matched, don't reuse it for scoring.
You will then add up all the graded component marks to calculate total-marks and output it as: {The total marks is total-marks.}
Provide the reasoning for marking the components, but don't repeat the assignment question, the student's answer or the rubric.
"""


SCORING_REPORT_PROMPT = """You are a scoring assistant for the course "<<course_name>>", which covers <<course_topics>>. You are evaluating a student's submitted **report** (a lab/project write-up submitted as a PDF) against a holistic rubric — there are no per-question splits; the rubric describes the criteria for the report as a whole.
Inputs you may receive in a single user turn:
  - {Relevant course material:} — RAG-retrieved excerpts from course PDFs.
  - {The assignment problem statement is:} — the prompt the student was responding to.
  - {The scoring rubric (PDF) is attached.} — the rubric arrives as an attached PDF Part. Read its criteria, marks allocations, and any worked examples from the PDF directly.
  - {The scoring rubric (text) is:} — fallback / supplemental rubric in plain text.
  - {A sample graded response (for reference, not for re-grading):} — a one-shot example of how a graded response should read.
  - {The student's submitted report (PDF) is attached.} — the student's work, also as an attached PDF Part. Inspect figures, tables, plots, and code listings inside the PDF, not just the prose.
  - For regrades you may also see {The agent's previous grading was:} and {The student contends:} — re-evaluate fairly, weighing the contention against the rubric, but anchor your judgment in the rubric and the report itself.
How to grade:
  1. Walk through each rubric criterion in order.
  2. For each criterion, decide whether the report fully meets it, partially meets it, or misses it. Cite specific evidence from the report (figure 3, section 2.1, code in appendix, etc.) — do **not** copy whole paragraphs of the report back.
  3. Award marks per criterion, not exceeding the rubric's allocation. Total awarded marks must not exceed the rubric's stated maximum.
  4. Conclude with exactly one summary line of the form: "The total marks is <number>." (this is what the server parses to extract the score).
Be concise, fair, and grounded. Don't fabricate criteria the rubric doesn't have. If the report is partially missing or unreadable in places, flag that rather than guessing.
"""


# --- Placeholder substitution ----------------------------------------------

_PLACEHOLDER_NAME = "<<course_name>>"
_PLACEHOLDER_TOPICS = "<<course_topics>>"


def format_prompt(template: str, course_name: str = "", course_topics: str = "") -> str:
    """Substitute ``<<course_name>>`` / ``<<course_topics>>`` in *template*.

    Uses literal string replacement so the existing ``{...}`` markers in the
    prompts (which the agents treat as content delimiters) are left untouched.
    Falls back to readable defaults when either course field is empty so the
    rendered prompt is still grammatical for courses that haven't filled
    these in yet.
    """
    name = course_name.strip() if course_name else ""
    topics = course_topics.strip() if course_topics else ""
    return (template
            .replace(_PLACEHOLDER_NAME, name or DEFAULT_COURSE_NAME_FALLBACK)
            .replace(_PLACEHOLDER_TOPICS, topics or DEFAULT_COURSE_TOPICS_FALLBACK))


# --- Agent factory ---------------------------------------------------------

_agent_cache = {}

_AGENT_CONFIGS = {
    "instructor": {
        "name": "instructor_assist_agent",
        "description": "An assistant to help the course instructor.",
        "instruction": INSTRUCTOR_ASSIST_PROMPT,
    },
    "student": {
        "name": "ai_tutor_agent",
        "description": "A teaching assistant agent.",
        "instruction": STUDENT_ASSIST_PROMPT,
    },
    "scoring_qa": {
        "name": "ai_scoring_qa_agent",
        "description": "A scoring agent for per-question (q&a) assignments.",
        "instruction": SCORING_QA_PROMPT,
    },
    "scoring_report": {
        "name": "ai_scoring_report_agent",
        "description": "A scoring agent for holistic report assignments.",
        "instruction": SCORING_REPORT_PROMPT,
    },
    # Back-compat: "scoring" is an alias for the q&a scorer (the only
    # scorer the platform had before the q&a/report split).
    "scoring": {
        "name": "ai_scoring_agent",
        "description": "A scoring agent (legacy alias for scoring_qa).",
        "instruction": SCORING_QA_PROMPT,
    },
}


def create_agent(
    agent_type: str,
    model: str = DEFAULT_MODEL,
    instruction: str | None = None,
    course_handle: str | None = None,
    course_name: str = "",
    course_topics: str = "",
) -> Agent:
    """Create (or return cached) Agent for the given type, model, and course.

    Args:
        agent_type: One of ``"instructor"``, ``"student"``, ``"scoring_qa"``,
            ``"scoring_report"``, or the legacy ``"scoring"`` alias.
        model: The Gemini model name.
        instruction: Optional per-course override prompt (set via
            /update_course_prompt). When provided, replaces the default
            template — but is *also* run through ``format_prompt`` so the
            instructor can use the same ``<<course_name>>`` /
            ``<<course_topics>>`` placeholders in their override.
        course_handle: Optional course identifier for per-course caching.
        course_name: Filled into the ``<<course_name>>`` placeholder.
        course_topics: Filled into the ``<<course_topics>>`` placeholder.
    """
    key = (agent_type, model, course_handle)
    if key in _agent_cache:
        return _agent_cache[key]

    cfg = _AGENT_CONFIGS.get(agent_type)
    if not cfg:
        raise ValueError(f"Unknown agent type: {agent_type}")

    template = instruction if instruction else cfg["instruction"]
    rendered = format_prompt(template, course_name=course_name, course_topics=course_topics)

    agent_kwargs = {k: v for k, v in cfg.items() if k != "instruction"}
    agent_kwargs["instruction"] = rendered

    ag = Agent(model=model, **agent_kwargs)
    _agent_cache[key] = ag
    return ag


def get_default_prompt(agent_type: str) -> str:
    """Return the raw default prompt template for *agent_type*.

    The returned string still contains the ``<<course_name>>`` /
    ``<<course_topics>>`` placeholders — exposed for the GET /course_prompt
    endpoint so the dashboard can show instructors the unformatted template.
    """
    cfg = _AGENT_CONFIGS.get(agent_type)
    if not cfg:
        raise ValueError(f"Unknown agent type: {agent_type}")
    return cfg["instruction"]


def list_agent_types() -> list[str]:
    """Return the agent type identifiers callers can use."""
    return list(_AGENT_CONFIGS.keys())


# --- Default agents (used by config.py for backward-compatible runners) ---

instructor_assist_agent = create_agent("instructor")
student_assist_agent = create_agent("student")
scoring_assist_agent = create_agent("scoring")  # legacy alias = scoring_qa
