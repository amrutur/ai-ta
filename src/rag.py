"""
RAG (Retrieval-Augmented Generation) pipeline for course materials.

Indexes PDF files from GCS into Firestore with vector embeddings,
and retrieves relevant chunks at query time to augment agent prompts.
"""

import asyncio
import io
import logging

from google.cloud import storage
from google.cloud.firestore_v1.vector import Vector
from google.cloud.firestore_v1.base_vector_query import DistanceMeasure
from google.oauth2 import service_account
from pypdf import PdfReader
from vertexai.language_models import TextEmbeddingModel

import config

logger = logging.getLogger(__name__)

EMBEDDING_MODEL_NAME = "text-embedding-004"
CHUNK_SIZE = 1000
CHUNK_OVERLAP = 200
RAG_SUBCOLLECTION = "rag_chunks"
EMBEDDING_BATCH_SIZE = 250  # Vertex AI per-request limit


def _get_storage_client():
    """Create a GCS client using the service account credentials."""
    credentials = service_account.Credentials.from_service_account_info(
        config.firestore_cred_dict
    )
    return storage.Client(credentials=credentials, project=config.bucket_name.split('-')[0])


def _extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract all text from a PDF file."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    pages = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            pages.append(text)
    return "\n\n".join(pages)


def _chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start += chunk_size - overlap
    return chunks


def _embed_texts(texts: list[str], task_type: str = "RETRIEVAL_DOCUMENT") -> list[list[float]]:
    """Generate embeddings using Vertex AI's text embedding model."""
    model = TextEmbeddingModel.from_pretrained(EMBEDDING_MODEL_NAME)
    all_embeddings = []
    for i in range(0, len(texts), EMBEDDING_BATCH_SIZE):
        batch = texts[i:i + EMBEDDING_BATCH_SIZE]
        results = model.get_embeddings(batch, output_dimensionality=768)
        all_embeddings.extend([e.values for e in results])
    return all_embeddings


async def build_course_index(course_handle: str, folder_name: str) -> dict:
    """Build the RAG index for a course by processing all PDFs in its GCS folder.

    Args:
        course_handle: The course identifier.
        folder_name: The GCS path in format "bucket_name/prefix/".

    Returns:
        A dict with status, files_processed, and chunks_created.
    """
    parts = folder_name.split('/', 1)
    bucket_name = parts[0]
    prefix = parts[1] if len(parts) > 1 else ''

    # List PDF files in GCS
    client = _get_storage_client()
    bucket = client.bucket(bucket_name)
    blobs = await asyncio.to_thread(lambda: list(bucket.list_blobs(prefix=prefix)))
    pdf_blobs = [b for b in blobs if b.name.lower().endswith('.pdf')]

    if not pdf_blobs:
        return {"status": "no_pdfs", "files_processed": 0, "chunks_created": 0,
                "message": "No PDF files found in course folder"}

    db = config.db

    # Delete existing chunks for this course
    chunks_ref = db.collection("courses").document(course_handle).collection(RAG_SUBCOLLECTION)
    existing_docs = chunks_ref.stream()
    async for doc in existing_docs:
        await doc.reference.delete()
    logger.info(f"Cleared existing RAG chunks for course {course_handle}")

    total_chunks = 0
    files_processed = 0

    for blob in pdf_blobs:
        try:
            pdf_bytes = await asyncio.to_thread(blob.download_as_bytes)
            text = await asyncio.to_thread(_extract_text_from_pdf, pdf_bytes)
            if not text.strip():
                logger.warning(f"No text extracted from {blob.name}")
                continue

            chunks = _chunk_text(text)
            if not chunks:
                continue

            # Generate embeddings
            embeddings = await asyncio.to_thread(_embed_texts, chunks)

            # Store chunks with embeddings in Firestore
            for idx, (chunk_text, embedding) in enumerate(zip(chunks, embeddings)):
                await chunks_ref.add({
                    "source_file": blob.name.split('/')[-1],
                    "chunk_index": idx,
                    "text": chunk_text,
                    "embedding": Vector(embedding),
                })
                total_chunks += 1

            files_processed += 1
            logger.info(f"Indexed {blob.name}: {len(chunks)} chunks")

        except Exception as e:
            logger.error(f"Failed to index {blob.name}: {e}")
            continue

    logger.info(f"RAG index built for {course_handle}: {files_processed} files, {total_chunks} chunks")
    return {
        "status": "success",
        "files_processed": files_processed,
        "chunks_created": total_chunks,
    }


async def retrieve_context(course_handle: str, query: str, top_k: int = 5) -> str:
    """Retrieve relevant course material chunks for a query.

    Args:
        course_handle: The course identifier.
        query: The user's query text.
        top_k: Number of chunks to retrieve.

    Returns:
        Formatted string of relevant course material, or empty string if none found.
    """
    db = config.db
    chunks_ref = db.collection("courses").document(course_handle).collection(RAG_SUBCOLLECTION)

    # Embed the query
    query_embedding = await asyncio.to_thread(
        _embed_texts, [query], "RETRIEVAL_QUERY"
    )

    if not query_embedding:
        return ""

    try:
        results = chunks_ref.find_nearest(
            vector_field="embedding",
            query_vector=Vector(query_embedding[0]),
            distance_measure=DistanceMeasure.COSINE,
            limit=top_k,
        )

        docs = []
        async for doc in results.stream():
            data = doc.to_dict()
            source = data.get("source_file", "unknown")
            text = data.get("text", "")
            docs.append(f"[Source: {source}]\n{text}")

        if not docs:
            return ""

        return "\n\n---\n\n".join(docs)

    except Exception as e:
        logger.warning(f"RAG retrieval failed for course {course_handle}: {e}")
        return ""
