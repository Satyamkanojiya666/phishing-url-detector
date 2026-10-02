import io

import pytest

import app as app_module


@pytest.fixture()
def client(tmp_path):
    app_module.app.config.update(TESTING=True, DB_PATH=str(tmp_path / "t.db"), RATE_LIMIT=1000)
    app_module._hits.clear()
    return app_module.app.test_client()


def test_index_and_health(client):
    assert client.get("/").status_code == 200
    assert client.get("/api/health").get_json()["status"] == "ok"


def test_analyze_and_history(client):
    r = client.post("/api/analyze", json={"text": "Your OTP is 482913. Share this with our agent for refund."})
    assert r.status_code == 200 and r.get_json()["verdict"] != "SAFE"
    hist = client.get("/api/history").get_json()
    assert len(hist) == 1 and hist[0]["kind"] == "message"


def test_validation(client):
    assert client.post("/api/analyze", json={"text": "  "}).status_code == 400
    assert client.post("/api/analyze", json={"text": "x" * 6000}).status_code == 413
    assert client.post("/api/analyze", json={"text": 123}).status_code == 400


def test_url_scan(client):
    r = client.post("/api/url", json={"url": "http://amaz0n-prize.xyz"})
    assert r.get_json()["verdict"] == "PHISHING / SCAM"


def test_batch_json_and_file(client):
    r = client.post("/api/batch", json={"messages": ["Hi, lunch at 1?", "URGENT verify KYC http://bit.ly/x now"]})
    d = r.get_json()
    assert d["count"] == 2 and sum(d["summary"].values()) == 2
    f = client.post("/api/batch", data={"file": (io.BytesIO(b"hello friend\nwon a lottery, send bank details"), "m.txt")},
                    content_type="multipart/form-data")
    assert f.get_json()["count"] == 2


def test_feedback_and_stats(client):
    rid = client.post("/api/analyze", json={"text": "hello there"}).get_json()["id"]
    assert client.post("/api/feedback", json={"id": rid, "correct": True}).status_code == 200
    assert client.post("/api/feedback", json={"id": 9999, "correct": True}).status_code == 404
    s = client.get("/api/stats").get_json()
    assert s["feedback_total"] == 1 and s["checked_count"] == 1


def test_export_blocks_formula_injection(client):
    client.post("/api/analyze", json={"text": "=HYPERLINK(\"http://evil\")"})
    body = client.get("/api/export").get_data(as_text=True)
    assert "'=HYPERLINK" in body


def test_clear_history(client):
    client.post("/api/analyze", json={"text": "hello"})
    client.delete("/api/history")
    assert client.get("/api/history").get_json() == []


def test_rate_limit(client):
    app_module.app.config["RATE_LIMIT"] = 2
    codes = [client.post("/api/analyze", json={"text": "hi"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_security_headers(client):
    assert client.get("/").headers["X-Content-Type-Options"] == "nosniff"
