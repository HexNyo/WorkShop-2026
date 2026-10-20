from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.main import create_app, load_sections, search, terms

DOC = """# Runbooks

## PB-INTEGRITY-RESTORE
Quarantaine synthétique : payment-api passe en SYNTHETIC_ONLY puis répare le grand livre.

## PB-SERVICE-RESTART
Redémarre le conteneur via le socket-proxy.
"""


def kb(tmp_path: Path) -> Path:
    (tmp_path / "runbooks.md").write_text(DOC, encoding="utf-8")
    return tmp_path


def test_search_ranks_matching_section_first(tmp_path):
    hits = search(load_sections(kb(tmp_path)), "Pourquoi payment-api est-il en SYNTHETIC_ONLY ?")
    assert hits[0][0].title == "PB-INTEGRITY-RESTORE"
    assert 0 < hits[0][1] <= 1


def test_terms_keep_short_codes_and_fold_plurals():
    assert terms("Contrôle V8 : étapes des playbooks") == {"contrôle", "v8", "étape", "playbook"}


def test_chat_sends_excerpts_and_returns_sources(tmp_path):
    seen = {}

    def ollama(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"message": {"content": "Quarantaine synthétique."}})

    client = TestClient(create_app(kb(tmp_path), httpx.MockTransport(ollama)))
    reply = client.post("/v1/chat", json={"conversation_id": None, "message": "SYNTHETIC_ONLY ?", "context": {}}).json()
    assert reply["answer"] == "Quarantaine synthétique."
    assert reply["sources"][0]["uri"] == "kb://runbooks#pb-integrity-restore"
    assert "num_ctx" in seen["body"] and "grand livre" in seen["body"]


def test_chat_maps_ollama_outage_to_503(tmp_path):
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = TestClient(create_app(kb(tmp_path), httpx.MockTransport(down)))
    assert client.post("/v1/chat", json={"message": "SYNTHETIC_ONLY"}).status_code == 503


def test_chat_without_match_skips_model(tmp_path):
    client = TestClient(create_app(kb(tmp_path), httpx.MockTransport(lambda r: httpx.Response(500))))
    reply = client.post("/v1/chat", json={"message": "zzzz"}).json()
    assert reply["sources"] == [] and "aucun passage" in reply["answer"]
