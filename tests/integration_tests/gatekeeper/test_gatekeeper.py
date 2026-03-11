import pytest
import requests
import json


def test_signup_basic():
    res = requests.post(
        "http://127.0.0.1:8081/signup",
        json={"username": "test", "password": "test", "email": "test@test.com"},
    )

    assert res.reason == "OK"
    assert res.status_code == 200
    print(res.text)
    assert res.text == '{"reason":"user created","user_created":true}'


def test_token_basic():
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
