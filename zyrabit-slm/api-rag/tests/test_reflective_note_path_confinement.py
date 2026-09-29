"""Regression tests for GHSA-x5v6-gwgg-7vf8 (CWE-22) session_id path traversal."""
import asyncio
from unittest.mock import MagicMock
import pytest
from pydantic import ValidationError

from app.api.v1.endpoints.chat import ChatQuery
from app.domain.services.obsidian_service import ObsidianService
from app.infrastructure.shared.state_tracker import SovereignStateManager


def test_chat_query_rejects_path_traversal_session_id():
    """Verify Pydantic schema blocks directory traversal in session_id."""
    with pytest.raises(ValidationError):
        ChatQuery(text="hello", session_id="../../app/main.py")

    with pytest.raises(ValidationError):
        ChatQuery(text="hello", session_id="/etc/passwd")

    with pytest.raises(ValidationError):
        ChatQuery(text="hello", session_id="..\\windows\\traversal")


def test_chat_query_accepts_valid_session_id():
    """Verify valid alphanumeric and hyphen/underscore session_ids pass."""
    query = ChatQuery(text="hello", session_id="valid-session_123")
    assert query.session_id == "valid-session_123"


def test_obsidian_service_blocks_path_traversal(tmp_path, monkeypatch):
    """Verify generate_reflective_note confines files strictly to Reflective Notes folder."""
    vault_dir = tmp_path / "vault"
    monkeypatch.setattr(ObsidianService, "VAULT_PATH", vault_dir)
    monkeypatch.setattr(SovereignStateManager, "DB_PATH", str(tmp_path / "state.db"))
    monkeypatch.setattr(
        SovereignStateManager,
        "get_history",
        lambda session_id: [{"role": "user", "content": "hello"}],
    )
    monkeypatch.setattr(
        SovereignStateManager,
        "get_user_profile",
        lambda: {"user_name": "Test", "preferred_model": "qwen2.5:7b"},
    )

    mock_provider = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "Reflective note body"
    mock_provider.generate.return_value = mock_response

    # Attempt to inject path traversal directly
    traversal_payload = "../../evil"
    result = asyncio.run(
        ObsidianService.generate_reflective_note(
            session_id=traversal_payload,
            inference_provider=mock_provider,
        )
    )

    # Nothing should exist outside vault
    assert not (tmp_path / "evil").exists()
    assert not (vault_dir.parent / "evil").exists()

    # The file created inside Reflective Notes must be safely sanitized
    notes_dir = vault_dir / "Reflective Notes"
    assert notes_dir.exists()
    created_files = list(notes_dir.iterdir())
    assert len(created_files) == 1
    for file in created_files:
        assert ".." not in file.name
        assert file.is_file()
