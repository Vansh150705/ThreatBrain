def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_requires_auth(client):
    assert client.get("/api/v1/threats").status_code == 401
