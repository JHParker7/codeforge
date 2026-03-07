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
        "http://127.0.0.1:8081/user/019cc3a4-cadf-7e26-80f1-05ed020a352a",
        headers={"Authorization": f"Bearer: {json.loads(res.text)['token']}"},
    )

    assert res.reason == "OK"
    assert res.status_code == 200

    print(res.text)

    assert False
