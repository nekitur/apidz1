import datetime
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_create_link_success():
    response = client.post("/links/shorten", params={"original_url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "short_code" in data
    assert data["original_url"] == "https://example.com"

def test_create_link_invalid_data():
    response = client.post("/links/shorten")
    assert response.status_code == 422

def test_get_link_redirection():
    response = client.post("/links/shorten", params={"original_url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    short_code = data["short_code"]

    redirect_response = client.get(f"/{short_code}", follow_redirects=False)
    assert redirect_response.status_code in (302, 307)
    assert redirect_response.headers.get("location") == "https://example.com"

def test_link_stats():
    response = client.post("/links/shorten", params={"original_url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    short_code = data["short_code"]

    stats_response = client.get(f"/links/{short_code}/stats")
    assert stats_response.status_code == 200
    stats = stats_response.json()
    assert stats["original_url"] == "https://example.com"
    assert "created_at" in stats

def test_register_and_login():
    register_resp = client.post("/register", json={"username": "testuser", "password": "testpass"})
    assert register_resp.status_code == 200
    reg_data = register_resp.json()
    assert "message" in reg_data

    login_resp = client.post("/login", data={"username": "testuser", "password": "testpass"})
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert "access_token" in login_data

def test_update_and_delete_link():
    create_resp = client.post("/links/shorten", params={"original_url": "https://example.com"})
    assert create_resp.status_code == 200
    data = create_resp.json()
    short_code = data["short_code"]

    client.post("/register", json={"username": "upduser", "password": "updpass"})
    login_resp = client.post("/login", data={"username": "upduser", "password": "updpass"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    update_resp = client.put(f"/links/{short_code}", params={"original_url": "https://newexample.com"}, headers=headers)
    assert update_resp.status_code in (403, 404)

    delete_resp = client.delete(f"/links/{short_code}", headers=headers)
    assert delete_resp.status_code in (403, 404)

def test_search_and_expired_links():
    past = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()
    create_resp = client.post("/links/shorten", params={"original_url": "https://searchexample.com", "expires_at": past})
    assert create_resp.status_code == 200
    data = create_resp.json()
    short_code = data["short_code"]

    search_resp = client.get("/links/search", params={"original_url": "https://searchexample.com"})
    assert search_resp.status_code == 200
    search_data = search_resp.json()
    assert isinstance(search_data, list) and len(search_data) >= 1

    expired_resp = client.get("/links/expired")
    assert expired_resp.status_code == 200
    expired_data = expired_resp.json()
    found = any(link["short_code"] == short_code for link in expired_data)
    assert found

def test_cleanup_links():
    client.post("/register", json={"username": "cleanupuser", "password": "cleanuppass"})
    login_resp = client.post("/login", data={"username": "cleanupuser", "password": "cleanuppass"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=100)).isoformat()
    create_resp = client.post("/links/shorten", params={"original_url": "https://cleanupexample.com", "expires_at": past_date})
    assert create_resp.status_code == 200

    cleanup_resp = client.delete("/cleanup-links", headers=headers)
    assert cleanup_resp.status_code == 200
    cleanup_data = cleanup_resp.json()
    assert "Удалено" in cleanup_data.get("message", "")

def test_create_link_custom_alias():
    response = client.post("/links/shorten", params={"original_url": "https://custom.com", "custom_alias": "myalias"})
    assert response.status_code == 200
    data = response.json()
    assert data["short_code"] == "myalias"

    response2 = client.post("/links/shorten", params={"original_url": "https://other.com", "custom_alias": "myalias"})
    assert response2.status_code == 400

def test_redirect_expired_link():
    past = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()
    response = client.post("/links/shorten", params={"original_url": "https://expired.com", "expires_at": past})
    assert response.status_code == 200
    data = response.json()
    short_code = data["short_code"]

    from app.main import redis_client
    redis_client.delete(short_code)

    redirect_resp = client.get(f"/{short_code}", follow_redirects=False)
    assert redirect_resp.status_code == 410


def test_update_and_delete_link_owner_success():
    client.post("/register", json={"username": "owner", "password": "ownerpass"})
    login_resp = client.post("/login", data={"username": "owner", "password": "ownerpass"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/links/shorten", params={"original_url": "https://owned.com"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    short_code = data["short_code"]

    update_resp = client.put(f"/links/{short_code}", params={"original_url": "https://updated.com"}, headers=headers)
    assert update_resp.status_code == 200
    update_data = update_resp.json()
    assert update_data["message"] == "Ссылка обновлена"

    delete_resp = client.delete(f"/links/{short_code}", headers=headers)
    assert delete_resp.status_code == 200
    delete_data = delete_resp.json()
    assert delete_data["message"] == "Ссылка удалена"

def test_login_failure():
    login_resp = client.post("/login", data={"username": "nonexist", "password": "wrong"})
    assert login_resp.status_code == 401
