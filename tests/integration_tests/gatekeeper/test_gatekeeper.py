import pytest
import requests


def test_signup_basic():
    res = requests.put(
        "http://127.0.0.1:8081/signup",
        json={"username": "test", "password": "test", "email": "test@test.com"},
    )

    print(res.reason)
    # print(res.json())
    print(res.json())
    print(res.status_code)
    pytest.fail()
