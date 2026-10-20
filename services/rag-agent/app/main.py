"""Agent documentaire : recherche lexicale dans docs/ puis génération locale via Ollama (gratuit, hors ligne).

L'authentification (rôle noc.viewer) et la limitation de débit sont faites par la passerelle :
ce service n'est joignable que sur le réseau interne `app`.
"""

from __future__ import annotations

import math
import os
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse

from ra_common.health import health_response
from ra_common.middleware import RequestContextMiddleware
from ra_common.problem import install_problem_handlers, unavailable

SERVICE, VERSION = "rag-agent", "1.0.0"
KB_DIR = Path(os.environ.get("RAG_KB_DIR", "/srv/kb"))
OLLAMA_URL = os.environ.get("RAG_OLLAMA_URL", "http://ollama:11434")
MODEL = os.environ.get("RAG_MODEL", "qwen2.5:7b")
TOP_K = 5
CHUNK_CHARS = 1500  # 5 extraits ≈ 2,5k tokens : tient dans num_ctx avec la question et la réponse
OLLAMA_TIMEOUT_S = 55.0  # la passerelle coupe à 60 s

SYSTEM_PROMPT = (
    "Tu es l'assistant des opérateurs NOC/SOC de la plateforme RESILIENCE-ALPHA. "
    "Réponds en français, de façon concise, UNIQUEMENT à partir des extraits de documentation fournis. "
    "Si la réponse n'y figure pas, dis clairement que la documentation ne le précise pas. "
    "N'invente jamais de commande, de playbook ou de code d'erreur."
)

_WORD = re.compile(r"[\w-]{2,}")
_IDENTIFIER = re.compile(r"[-_\d]")  # PB-INTEGRITY-RESTORE, SYNTHETIC_ONLY, V8…
_HEADING = re.compile(r"^(#{1,3}|-- [a-z_]+ :)\s+(.*)$")  # titres Markdown, ou "-- schéma : titre" du seed SQL
_STOPWORDS = frozenset(
    "les des une est que qui pour dans par sur avec pas son ses aux the and quoi quel quelle quels quelles "
    "comment pourquoi faire fait été être sont cette ces mais plus tout tous elle ils".split()
)


def terms(text: str) -> set[str]:
    # Pluriel réduit au singulier (étapes -> étape, playbooks -> playbook) : stemming minimal suffisant ici.
    words = (w for w in _WORD.findall(text.lower()) if (len(w) > 2 or _IDENTIFIER.search(w)) and w not in _STOPWORDS)
    return {w[:-1] if len(w) > 4 and w.endswith("s") else w for w in words}


@dataclass(frozen=True)
class Section:
    title: str
    uri: str
    text: str
    terms: frozenset[str]


def load_sections(kb_dir: Path) -> list[Section]:
    """Découpe chaque fichier (Markdown, SQL du catalogue de playbooks) en extraits sous leur titre #, ## ou ###."""
    sections: list[Section] = []
    for path in sorted([*kb_dir.glob("*.md"), *kb_dir.glob("*.sql")]):
        title, lines = path.stem, []

        def flush() -> None:
            # Les longues sections (diagrammes, tableaux) sont découpées par paragraphes : un passage précis
            # n'est ni noyé dans le score, ni tronqué dans le prompt.
            slug = re.sub(r"[^\w]+", "-", title.lower()).strip("-")
            chunks: list[str] = []
            # Coupe aussi avant chaque ligne "(" : un tuple SQL (un playbook du seed) reste dans un seul extrait.
            paras = re.split(r"\n\s*\n|\n(?=\(\n)", "\n".join(lines))
            for para in (piece for p in paras for piece in (p.split("\n") if len(p) > CHUNK_CHARS else [p])):
                if chunks and len(chunks[-1]) + len(para) < CHUNK_CHARS:
                    chunks[-1] += "\n\n" + para
                elif para.strip():
                    chunks.append(para)
            for i, chunk in enumerate(c.strip() for c in chunks):
                uri = f"kb://{path.stem}#{slug}" + (f"-{i + 1}" if i else "")
                sections.append(Section(title, uri, chunk, frozenset(terms(title + " " + chunk))))

        for line in path.read_text(encoding="utf-8").splitlines():
            match = _HEADING.match(line)
            if match:
                flush()
                title, lines = match.group(2).strip(), []
            else:
                lines.append(line)
        flush()
    return sections


def search(sections: list[Section], query: str, k: int = TOP_K) -> list[tuple[Section, float]]:
    """Classement par somme des IDF des mots de la question présents dans l'extrait, normalisé sur [0, 1].

    Les identifiants comptent double : les opérateurs interrogent par code (playbook, contrôle, statut).
    """
    query_terms = terms(query)
    n = len(sections)
    idf = {
        t: math.log(1 + n / (1 + sum(t in s.terms for s in sections))) * (2 if _IDENTIFIER.search(t) else 1)
        for t in query_terms
    }
    best = sum(idf.values()) or 1.0
    scored = [(s, sum(idf[t] for t in query_terms & s.terms) / best) for s in sections]
    return sorted((x for x in scored if x[1] > 0), key=lambda x: x[1], reverse=True)[:k]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChatContext(StrictModel):
    incident_id: str | None = Field(default=None, max_length=64)
    phase: str | None = Field(default=None, max_length=32)


class ChatRequest(StrictModel):
    conversation_id: str | None = Field(default=None, max_length=64)
    message: str = Field(min_length=1, max_length=2000)
    context: ChatContext = Field(default_factory=ChatContext)


def create_app(kb_dir: Path = KB_DIR, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    sections = load_sections(kb_dir)
    app = FastAPI(title="RESILIENCE-ALPHA rag-agent", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    install_problem_handlers(app)
    app.add_middleware(RequestContextMiddleware)

    @app.get("/health/liveness")
    async def liveness() -> JSONResponse:
        return health_response(service=SERVICE, version=VERSION, extra={"sections": len(sections), "model": MODEL})

    @app.post("/v1/chat")
    async def chat(body: ChatRequest) -> dict:
        hits = search(sections, body.message)
        if hits:
            excerpts = "\n\n".join(f"### {s.title} ({s.uri})\n{s.text}" for s, _ in hits)
            ctx = body.context
            console = f"Contexte console : phase={ctx.phase or 'inconnue'}, incident={ctx.incident_id or 'aucun'}.\n\n"
            async with httpx.AsyncClient(base_url=OLLAMA_URL, timeout=OLLAMA_TIMEOUT_S, transport=transport) as client:
                try:
                    response = await client.post(
                        "/api/chat",
                        json={
                            "model": MODEL,
                            "stream": False,
                            # Ollama tronque silencieusement à 2-4k tokens sans num_ctx explicite.
                            "options": {"num_ctx": 8192, "temperature": 0.2},
                            "messages": [
                                {"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": f"{console}Extraits :\n{excerpts}\n\nQuestion : {body.message}"},
                            ],
                        },
                    )
                    response.raise_for_status()
                    answer = response.json()["message"]["content"].strip()
                except (httpx.HTTPError, KeyError, ValueError) as exc:
                    raise unavailable(f"Modèle local indisponible ({exc.__class__.__name__})") from exc
        else:
            answer = (
                "La documentation ne contient aucun passage lié à cette question. "
                "Reformulez avec des termes précis (playbook, contrôle, statut…)."
            )
        return {
            "conversation_id": body.conversation_id or f"conv_{uuid.uuid4().hex}",
            "message_id": f"msg_{uuid.uuid4().hex}",
            "answer": answer,
            "sources": [
                {"title": s.title, "uri": s.uri, "excerpt": s.text[:280], "score": round(score, 2)} for s, score in hits
            ],
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }

    return app


app = create_app()
