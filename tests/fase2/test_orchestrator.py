"""Tests del orquestador. Mockea Splunk, Ollama y checkpoint."""
import json

import pytest

import bot2_siem.orchestrator as orch


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Aisla state.json por test y silencia logs."""
    monkeypatch.setattr(orch, "STATE_FILE", tmp_path / "state.json")
    yield


@pytest.fixture
def mock_splunk(mocker):
    """Mockea hec_send y search del modulo splunk_client (ya importados en orchestrator)."""
    hec = mocker.patch("bot2_siem.orchestrator.hec_send")
    search = mocker.patch("bot2_siem.orchestrator.search")
    return hec, search


@pytest.fixture
def mock_triage(mocker):
    return mocker.patch("bot2_siem.orchestrator.triage")


def _row(event_id="evt-1", **extra):
    base = {
        "event_id": event_id,
        "source_kind": "email",
        "timestamp": "2026-11-03T10:00:00Z",
        "_time": "2026-11-03T10:00:00Z",
        "summary": "test event",
    }
    base.update(extra)
    return base


# ---------- checkpoint ----------

def test_checkpoint_roundtrip():
    assert orch.load_checkpoint() == "-15m"
    orch.save_checkpoint("2026-11-03T10:00:00Z")
    assert orch.load_checkpoint() == "2026-11-03T10:00:00Z"


# ---------- process_batch ----------

def test_process_batch_happy_path(mock_splunk, mock_triage):
    hec, search = mock_splunk
    search.return_value = []  # verdict_exists -> False
    mock_triage.return_value = {"verdict": "malicious", "severity": "high", "reason": "bad exe"}

    stats = orch.process_batch([_row()])

    assert stats["processed"] == 1
    assert stats["failed"] == 0
    assert stats["skipped_dup"] == 0
    mock_triage.assert_called_once()
    hec.assert_called_once()
    # Verificar payload escrito
    _, kwargs = hec.call_args
    written = kwargs if kwargs else hec.call_args[0][0]
    # hec_send(output, sourcetype=...) -> usamos kwargs
    assert kwargs["sourcetype"] == "nirvana:secops:verdict"


def test_process_batch_idempotent(mock_splunk, mock_triage):
    hec, search = mock_splunk
    search.return_value = [{"event_id": "evt-1"}]  # verdict ya existe
    mock_triage.return_value = {"verdict": "benign", "severity": "low", "reason": "ok"}

    stats = orch.process_batch([_row("evt-1")])

    assert stats["skipped_dup"] == 1
    assert stats["processed"] == 0
    mock_triage.assert_not_called()
    hec.assert_not_called()


def test_process_batch_skips_invalid_event(mock_splunk, mock_triage):
    hec, search = mock_splunk
    search.return_value = []
    # source invalido -> falla validacion
    stats = orch.process_batch([_row(source_kind="telepathy")])

    assert stats["skipped_invalid"] == 1
    mock_triage.assert_not_called()
    hec.assert_not_called()


def test_process_batch_isolates_failures(mock_splunk, mock_triage):
    hec, search = mock_splunk
    search.return_value = []
    # Primer evento: triage explota. Segundo: OK.
    mock_triage.side_effect = [
        RuntimeError("ollama down"),
        {"verdict": "benign", "severity": "low", "reason": "ok"},
    ]

    stats = orch.process_batch([_row("evt-1"), _row("evt-2")])

    assert stats["failed"] == 1
    assert stats["processed"] == 1
    assert hec.call_count == 1


def test_process_batch_updates_checkpoint(mock_splunk, mock_triage):
    hec, search = mock_splunk
    search.return_value = []
    mock_triage.return_value = {"verdict": "benign", "severity": "low", "reason": "ok"}

    orch.process_batch([_row("evt-1", _time="2026-11-03T10:00:00Z")])
    assert orch.load_checkpoint() == "2026-11-03T10:00:00Z"

    orch.process_batch([_row("evt-2", _time="2026-11-03T11:00:00Z")])
    assert orch.load_checkpoint() == "2026-11-03T11:00:00Z"


def test_process_batch_empty():
    stats = orch.process_batch([])
    assert stats == {"processed": 0, "skipped_dup": 0, "skipped_invalid": 0,
                     "failed": 0, "last_time": None}


# ---------- run_once ----------

def test_run_once_uses_checkpoint_as_earliest(mock_splunk, mock_triage):
    hec, search = mock_splunk
    orch.save_checkpoint("2026-11-03T09:00:00Z")
    search.return_value = []
    orch.run_once()
    _, kwargs = search.call_args
    assert kwargs["earliest"] == "2026-11-03T09:00:00Z"