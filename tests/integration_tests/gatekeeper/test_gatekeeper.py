import base64
import psycopg2
import pytest
import requests
import json
import random

DB_DSN = "host=localhost port=5432 dbname=codeforge user=postgres password=test"


def test_signup_basic():
    res = requests.post(
        "http://127.0.0.1:8081/signup",
        json={
            "username": f"test{random.randint(1, 100000)}",
            "password": "test",
            "email": f"test{random.randint(1, 100000)}@test.com",
        },
    )

    assert res.reason == "OK"
    assert res.status_code == 200
    print(res.text)
    assert res.text == '{"reason":"user created","user_created":true}'


def test_token_basic_correct():
    res = requests.get(
        "http://127.0.0.1:8081/token",
        json={"username": "test", "password": "test"},
    )

    assert res.reason == "OK"
    assert res.status_code == 200


def test_token_basic_incorrect():
    res = requests.get(
        "http://127.0.0.1:8081/token",
        json={"username": "test", "password": "not_test"},
    )

    assert res.reason == "Unauthorized"
    assert res.status_code == 401


def test_get_user():
    res = requests.get(
        "http://127.0.0.1:8081/token",
        json={"username": "test", "password": "test"},
    )

    assert res.reason == "OK"
    assert res.status_code == 200

    print(res.text)

    res = requests.get(
        "http://127.0.0.1:8081/user/019cc784-cd17-7d02-8312-31175e7cf926",
        headers={"Authorization": f"Bearer: {json.loads(res.text)['token']}"},
    )

    assert res.reason == "OK"
    assert res.status_code == 200

    test_user = json.loads(res.text)

    assert test_user == {
        "id": "019cc784-cd17-7d02-8312-31175e7cf926",
        "username": "test",
        "password": "",
        "salt": "",
        "email": "test@test.com",
        "created_at": "0001-01-01T00:00:00Z",
        "updated_at": "0001-01-01T00:00:00Z",
        "role_id": {"String": "", "Valid": False},
        "team_id": {"String": "", "Valid": False},
        "org_id": {"String": "", "Valid": False},
        "active": False,
    }


def test_get_user_unauthorized():
    res = requests.get(
        "http://127.0.0.1:8081/user/019cc784-cd17-7d02-8312-31175e7cf926",
        headers={"Authorization": "Bearer: fake_token"},
    )

    assert res.reason == "Unauthorized"
    assert res.status_code == 401

    test_user = json.loads(res.text)

    assert test_user == {"code": 401, "message": "invaild token"}


def test_signup_creates_user_and_role():
    username = f"test{random.randint(1, 1000000)}"
    email = f"{username}@test.com"
    password = "testpass"

    # Sign up new user
    res = requests.post(
        "http://127.0.0.1:8081/signup",
        json={"username": username, "password": password, "email": email},
    )
    assert res.status_code == 200
    assert res.json() == {"reason": "user created", "user_created": True}

    # Authenticate to confirm the user exists in the database
    res = requests.get(
        "http://127.0.0.1:8081/token",
        json={"username": username, "password": password},
    )
    assert res.status_code == 200
    token = res.json()["token"]

    # Decode JWT payload to extract the user ID
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    claims = json.loads(base64.b64decode(payload))
    user_id = claims["id"]

    # Verify user was persisted with correct fields
    res = requests.get(
        f"http://127.0.0.1:8081/user/{user_id}",
        headers={"Authorization": f"Bearer: {token}"},
    )
    assert res.status_code == 200
    user = res.json()
    assert user["id"] == user_id
    assert user["username"] == username
    assert user["email"] == email

    # Verify the role was created in the database.
    # The role's permissions reference the user via "Gatekeeper/User/{user_id}".
    with psycopg2.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, permissions
                FROM auth.roles
                WHERE permissions::text LIKE %s
                """,
                (f"%Gatekeeper/User/{user_id}%",),
            )
            row = cur.fetchone()

    assert row is not None, f"no role found in DB for user {user_id}"
    role_id, permissions = row
    assert role_id != ""
    services = permissions["permissions"][0]["services"]
    assert f"Gatekeeper/User/{user_id}" in services
    actions = permissions["permissions"][0]["actions"]
    assert set(actions) == {"DeleteUser", "GetUser", "PutUser"}


def _signup_and_token(username, password):
    """Helper: sign up a new user and return their JWT token."""
    email = f"{username}@test.com"
    res = requests.post(
        "http://127.0.0.1:8081/signup",
        json={"username": username, "password": password, "email": email},
    )
    assert res.status_code == 200, f"signup failed: {res.text}"
    res = requests.get(
        "http://127.0.0.1:8081/token",
        json={"username": username, "password": password},
    )
    assert res.status_code == 200, f"token failed: {res.text}"
    return res.json()["token"]


def _user_id_from_token(token):
    """Decode JWT payload (no verification) and return the 'id' claim."""
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.b64decode(payload))["id"]


def test_delete_user_own_resource():
    username = f"del_int_{random.randint(1, 1000000)}"
    token = _signup_and_token(username, "testpass")
    user_id = _user_id_from_token(token)

    res = requests.delete(
        f"http://127.0.0.1:8081/user/{user_id}",
        headers={"Authorization": f"Bearer: {token}"},
    )
    assert res.status_code == 200
    assert res.json() == {"code": 200, "message": "user deleted"}

    # Confirm the token is now rejected (user soft-deleted, auth fails)
    res = requests.get(
        f"http://127.0.0.1:8081/user/{user_id}",
        headers={"Authorization": f"Bearer: {token}"},
    )
    assert res.status_code == 401


def test_delete_user_other_resource_forbidden():
    username = f"del_other_{random.randint(1, 1000000)}"
    token = _signup_and_token(username, "testpass")

    res = requests.delete(
        "http://127.0.0.1:8081/user/019cc784-cd17-7d02-8312-31175e7cf926",
        headers={"Authorization": f"Bearer: {token}"},
    )
    assert res.status_code == 403


def test_put_user_own_resource():
    username = f"put_int_{random.randint(1, 1000000)}"
    token = _signup_and_token(username, "testpass")
    user_id = _user_id_from_token(token)

    new_username = username + "_upd"
    new_email = new_username + "@test.com"

    res = requests.put(
        f"http://127.0.0.1:8081/user/{user_id}",
        headers={"Authorization": f"Bearer: {token}"},
        json={"username": new_username, "email": new_email},
    )
    assert res.status_code == 200
    assert res.json() == {"code": 200, "message": "user updated"}

    # Re-authenticate with new username to get a fresh token
    res = requests.get(
        "http://127.0.0.1:8081/token",
        json={"username": new_username, "password": "testpass"},
    )
    assert res.status_code == 200, f"re-auth failed: {res.text}"
    new_token = res.json()["token"]

    # Verify fields were updated
    res = requests.get(
        f"http://127.0.0.1:8081/user/{user_id}",
        headers={"Authorization": f"Bearer: {new_token}"},
    )
    assert res.status_code == 200
    user = res.json()
    assert user["username"] == new_username
    assert user["email"] == new_email


def test_put_user_other_resource_forbidden():
    username = f"put_other_{random.randint(1, 1000000)}"
    token = _signup_and_token(username, "testpass")

    res = requests.put(
        "http://127.0.0.1:8081/user/019cc784-cd17-7d02-8312-31175e7cf926",
        headers={"Authorization": f"Bearer: {token}"},
        json={"username": "hacked", "email": "hacked@test.com"},
    )
    assert res.status_code == 403


def test_get_user_no_match():
    res = requests.get(
        "http://127.0.0.1:8081/token",
        json={"username": "test", "password": "test"},
    )

    assert res.reason == "OK"
    assert res.status_code == 200

    print(res.text)

    res = requests.get(
        "http://127.0.0.1:8081/user/1",
        headers={"Authorization": f"Bearer: {json.loads(res.text)['token']}"},
    )

    assert res.reason == "OK"
    assert res.status_code == 200

    test_user = json.loads(res.text)

    assert test_user == {"code": 200, "message": "user not found"}
