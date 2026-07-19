import pytest

ENDPOINTS = [
    ("GET", "/", 200),
    ("GET", "/login", 200),
    ("GET", "/signup", 200),
    ("GET", "/login_submit", 405),
    ("GET", "/signup_submit", 405),
    ("GET", "/home_user", 302),
    ("GET", "/auth/google/callback", 405),
    ("GET", "/logout", 302),
]

@pytest.mark.parametrize("method,path,expected_status", ENDPOINTS)
def test_endpoints_respond(client, method, path, expected_status):
    resp = client.open(path, method=method)
    assert resp.status_code == expected_status
    assert resp.status_code != 500