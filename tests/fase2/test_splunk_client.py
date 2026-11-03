"""Tests de splunk_client con requests mockeado. No tocan Splunk real."""
import json

import pytest

import fase2_siem.splunk_client as sc


# ---------- hec_send ----------

def test_hec_send_success(mocker, monkeypatch):
    monkeypatch.setattr(sc, "HEC_TOKEN", "fake-token")
    mock_post = mocker.patch("fase2_siem.splunk_client.requests.post")
    mock_post.return_value.raise_for_status = lambda: None
    mock_post.return_value.json.return_value = {"text": "Success", "code": 0}

    ok = sc.hec_send({"hello": "world"})
    assert ok is True
    # Verificar headers y payload enviados
    _, kwargs = mock_post.call_args
    assert kwargs["headers"]["Authorization"] == "Splunk fake-token"
    body = json.loads(kwargs["data"])
    assert body["event"] == {"hello": "world"}
    assert body["sourcetype"] == "nirvana:secops:verdict"


def test_hec_send_raises_on_hec_error(mocker, monkeypatch):
    monkeypatch.setattr(sc, "HEC_TOKEN", "fake-token")
    mock_post = mocker.patch("fase2_siem.splunk_client.requests.post")
    mock_post.return_value.raise_for_status = lambda: None
    mock_post.return_value.json.return_value = {"text": "Invalid token", "code": 4}

    with pytest.raises(RuntimeError, match="HEC error"):
        sc.hec_send({"x": 1})


def test_hec_send_raises_without_token(monkeypatch):
    monkeypatch.setattr(sc, "HEC_TOKEN", "")
    with pytest.raises(RuntimeError, match="HEC_TOKEN no configurado"):
        sc.hec_send({"x": 1})


# ---------- search ----------

def test_search_parses_streaming_response(mocker):
    mock_post = mocker.patch("fase2_siem.splunk_client.requests.post")
    mock_post.return_value.raise_for_status = lambda: None
    # Splunk export devuelve NDJSON: lineas {result:{...}} o {preview:false}
    mock_post.return_value.text = "\n".join([
        json.dumps({"preview": False}),
        json.dumps({"result": {"_time": "2026-11-03T10:00:00Z", "host": "PC-A"}}),
        json.dumps({"result": {"_time": "2026-11-03T10:01:00Z", "host": "PC-B"}}),
        "",
    ])

    results = sc.search('index=* sourcetype="x"')
    assert len(results) == 2
    assert results[0]["host"] == "PC-A"
    assert results[1]["host"] == "PC-B"


def test_search_skips_invalid_json_lines(mocker):
    mock_post = mocker.patch("fase2_siem.splunk_client.requests.post")
    mock_post.return_value.raise_for_status = lambda: None
    mock_post.return_value.text = "not-json\n" + json.dumps({"result": {"ok": 1}}) + "\n"

    results = sc.search("index=*")
    assert len(results) == 1
    assert results[0]["ok"] == 1


def test_search_prepends_search_command(mocker):
    mock_post = mocker.patch("fase2_siem.splunk_client.requests.post")
    mock_post.return_value.raise_for_status = lambda: None
    mock_post.return_value.text = ""

    sc.search("index=* sourcetype=foo")

    _, kwargs = mock_post.call_args
    assert kwargs["data"]["search"].startswith("search ")


def test_search_does_not_duplicate_search_prefix(mocker):
    mock_post = mocker.patch("fase2_siem.splunk_client.requests.post")
    mock_post.return_value.raise_for_status = lambda: None
    mock_post.return_value.text = ""

    sc.search("search index=* sourcetype=foo")

    _, kwargs = mock_post.call_args
    assert kwargs["data"]["search"].count("search ") == 1