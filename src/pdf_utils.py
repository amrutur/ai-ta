"""
PDF utilities for the PDF-assignment ingest and grading flow.

Provides text extraction (used for author detection on the title page),
LLM-driven author extraction, name slug helpers for placeholder student IDs,
and fuzzy matching against an enrolled-student directory.
"""

import asyncio
import io
import json
import logging
import re
from typing import Optional

from pypdf import PdfReader
from rapidfuzz import fuzz, process

logger = logging.getLogger(__name__)

# Score (0–100, rapidfuzz scale) at or above which we consider a name to match
# an existing enrolled student. Below this we create a placeholder record.
NAME_MATCH_THRESHOLD = 85

# Domain used in synthesized student IDs for unmatched authors. The ".local"
# TLD is reserved (RFC 6762) and won't accidentally be a real address.
PLACEHOLDER_EMAIL_DOMAIN = "pending.local"

# How many leading pages to scan for author names. Most cover pages have all
# authors within the first one or two pages.
DEFAULT_AUTHOR_SCAN_PAGES = 3

# Hard cap on text sent to the author-extraction LLM. The first few pages of
# a normal report are well under this; this is just a safety net.
MAX_AUTHOR_PROMPT_CHARS = 6000


def extract_first_pages_text(pdf_bytes: bytes, max_pages: int = DEFAULT_AUTHOR_SCAN_PAGES) -> str:
    """Return concatenated text from the first *max_pages* of a PDF."""
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception as e:
        logger.warning(f"Failed to open PDF for text extraction: {e}")
        return ""
    pages = []
    for page in reader.pages[:max_pages]:
        try:
            text = page.extract_text() or ""
        except Exception as e:
            logger.warning(f"Failed to extract text from page: {e}")
            continue
        if text:
            pages.append(text)
    return "\n\n".join(pages)


def slugify_name(name: str) -> str:
    """Lowercase, hyphen-separated slug with only [a-z0-9-]."""
    slug = (name or "").lower().strip()
    slug = re.sub(r"\s+", "-", slug)
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug or "unknown"


def make_placeholder_student_id(name: str) -> str:
    """Stable synthetic student id for an unmatched author.

    Format: ``{slug}@pending.local`` — the domain itself signals that the
    record is auto-created and needs instructor cleanup.
    """
    return f"{slugify_name(name)}@{PLACEHOLDER_EMAIL_DOMAIN}"


def is_placeholder_student_id(student_id: str) -> bool:
    """Return True iff *student_id* was created by the PDF ingest flow."""
    return bool(student_id) and student_id.endswith(f"@{PLACEHOLDER_EMAIL_DOMAIN}")


async def extract_authors_with_gemini(
    pdf_text: str,
    model_name: str = "gemini-2.5-flash",
) -> list[str]:
    """Use a small Gemini call to pull author names from cover-page text.

    Uses structured output so we get a clean list back. Falls back to an
    empty list on any error — the ingest endpoint will then create a single
    placeholder student rather than failing the whole submission.
    """
    if not pdf_text or not pdf_text.strip():
        return []

    # Local import so module-level import doesn't fail in test envs that
    # mock out vertexai. agent.py calls vertexai.init() at import time.
    from vertexai.generative_models import GenerativeModel

    prompt = (
        "Extract the author names from this academic report or assignment "
        "cover page. Authors are usually listed below the title and may "
        "include affiliations, roll numbers, or email addresses — return "
        "ONLY the personal names, stripped of those extras. Return a JSON "
        "object with a single key 'authors' whose value is an array of "
        "full names (strings). If no authors can be identified, return "
        '{"authors": []}.'
        "\n\n---\n"
        f"{pdf_text[:MAX_AUTHOR_PROMPT_CHARS]}"
        "\n---"
    )

    schema = {
        "type": "object",
        "properties": {
            "authors": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["authors"],
    }

    try:
        model = GenerativeModel(model_name)
        response = await asyncio.to_thread(
            model.generate_content,
            prompt,
            generation_config={
                "response_mime_type": "application/json",
                "response_schema": schema,
            },
        )
        data = json.loads(response.text)
        authors = data.get("authors", [])
        return [a.strip() for a in authors if isinstance(a, str) and a.strip()]
    except Exception as e:
        logger.warning(f"Author extraction LLM call failed: {e}")
        return []


def match_author_to_student(
    author_name: str,
    student_directory: dict[str, str],
    threshold: int = NAME_MATCH_THRESHOLD,
) -> Optional[str]:
    """Fuzzy-match an extracted author name against enrolled-student names.

    Args:
        author_name: Name pulled from the PDF.
        student_directory: ``{student_id: display_name}`` for enrolled students.
            Entries with empty/missing names are ignored.
        threshold: rapidfuzz score (0–100) below which no match is returned.

    Returns:
        The matched ``student_id``, or ``None`` if nothing scored high enough.
    """
    if not author_name or not student_directory:
        return None

    name_to_id: dict[str, str] = {}
    for sid, display_name in student_directory.items():
        if display_name and display_name.strip():
            # Last writer wins on collisions — fine for fuzzy matching.
            name_to_id[display_name.strip()] = sid

    if not name_to_id:
        return None

    best = process.extractOne(
        author_name,
        list(name_to_id.keys()),
        scorer=fuzz.WRatio,
        score_cutoff=threshold,
    )
    if best is None:
        return None
    matched_name = best[0]
    return name_to_id[matched_name]
