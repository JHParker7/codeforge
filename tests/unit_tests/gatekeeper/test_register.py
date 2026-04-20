import asyncio
import pymongo
import pytest
import fastapi
from fastapi.testclient import TestClient

db = {}


@pytest.fixture()
def setup(monkeypatch):
    class MockTable:
        def __init__(self, name) -> None:
            if name not in db:
                db[name] = []
            self.name = name

        def insert_one(self, input: dict):
            db[self.name].append(input)
            db[self.name].append(input)

        def find_one(self, query=None):
            if not query:
                return db[self.name][0]
                return db[self.name][0]
            if query:
                filted_data = db[self.name]
                for key, value in query.items():
                    temp = []
                    # print(f"{key}={value}")
                    for x in filted_data:
                        if x[key] == value:
                            temp.append(x)
                    filted_data = temp
                filted_data = db[self.name]
                for key, value in query.items():
                    temp = []
                    # print(f"{key}={value}")
                    for x in filted_data:
                        if x[key] == value:
                            temp.append(x)
                    filted_data = temp
                if len(filted_data) != 0:
                    return filted_data[0]
                else:
                    return []

    class MockClient:
        def __init__(self, conn) -> None:
            pass

        def __getitem__(self, item):
            return MockDB()
            return MockDB()

    class MockDB:
        def __getitem__(self, item):
            return MockTable(item)

    monkeypatch.setattr(pymongo, "MongoClient", MockClient)
    import src.gatekeeper.main as gatekeeper

    client = TestClient(gatekeeper.app)
    yield (gatekeeper, client)


def test_new_user(setup):
    gatekeeper, client = setup
    global db
    db = {}
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))
    result["role_id"] = None
    result["user_id"] = None
    assert result == {
        "user_id": None,
        "username": "test",
        "email": "test@test.com",
        "full_name": "mr test",
        "role_id": None,
        "disabled": False,
    }
    role = db["roles"][0]
    role["role_id"] = None
    role["permissions"]["gatekeeper"]["services"][1] = None
    role["permissions"]["gatekeeper"]["services"][0] = (
        role["permissions"]["gatekeeper"]["services"][0].split("/")[0] + "/"
    )
    assert role == {
        "role_id": None,
        "permissions": {
            "gatekeeper": {
                "services": ["user/", None],
                "actions": [
                    "GetUser",
                    "DeleteUser",
                    "ListUsers",
                    "EditUser",
                    "GetRole",
                ],
            }
        },
    }


def test_duplicate_user(setup):
    gatekeeper, client = setup
    global db
    db = {}
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))
    result["role_id"] = None
    result["user_id"] = None
    assert result == {
        "user_id": None,
        "username": "test",
        "email": "test@test.com",
        "full_name": "mr test",
        "role_id": None,
        "disabled": False,
    }
    with pytest.raises(
        fastapi.exceptions.HTTPException, match=r".*409: user already exists.*"
    ):
        result = gatekeeper.register("test", "mr test", "test@test.com", "test")
        result = dict(asyncio.run(result))


def test_get_token(setup):
    gatekeeper, client = setup
    global db
    db = {}
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))

    class Token:
        def __init__(self) -> None:
            self.username = "test"
            self.password = "test"

    tokenInput = Token()
    result = gatekeeper.login_for_access_token(tokenInput)
    result = dict(asyncio.run(result))
    print(result)
    assert result["token_type"] == "bearer"
    token = result["access_token"]
    assert isinstance(token, str)
    print(len(token))
    assert len(token) == 187


def test_get_token_wrong_creds(setup):
    gatekeeper, client = setup
    global db
    db = {}
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))

    class Token:
        def __init__(self, username, password) -> None:
            self.username = username
            self.password = password

    tokenInput = Token("test", "test1")
    with pytest.raises(
        fastapi.exceptions.HTTPException,
        match=r".*401: Incorrect username or password.*",
    ):
        result = gatekeeper.login_for_access_token(tokenInput)
        result = dict(asyncio.run(result))
    tokenInput = Token("test1", "test")
    with pytest.raises(
        fastapi.exceptions.HTTPException,
        match=r".*401: Incorrect username or password.*",
    ):
        result = gatekeeper.login_for_access_token(tokenInput)
        result = dict(asyncio.run(result))
    tokenInput = Token("test1", None)
    with pytest.raises(
        TypeError,
        match=r"password must be str or bytes",
    ):
        result = gatekeeper.login_for_access_token(tokenInput)
        result = dict(asyncio.run(result))
    tokenInput = Token("test1", 1)
    with pytest.raises(
        TypeError,
        match=r"password must be str or bytes",
    ):
        result = gatekeeper.login_for_access_token(tokenInput)
        result = dict(asyncio.run(result))


def test_get_current_user(setup):
    gatekeeper, client = setup
    global db
    db = {}
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))

    class Token:
        def __init__(self) -> None:
            self.username = "test"
            self.password = "test"

    tokenInput = Token()
    result = gatekeeper.login_for_access_token(tokenInput)
    result = dict(asyncio.run(result))
    print(result)
    assert result["token_type"] == "bearer"
    token = result["access_token"]
    assert isinstance(token, str)
    print(len(token))
    assert len(token) == 187
    result = gatekeeper.get_current_user(token)
    result = dict(asyncio.run(result))
    print(result)
    result["role_id"] = None
    result["user_id"] = None
    assert result == {
        "user_id": None,
        "username": "test",
        "email": "test@test.com",
        "full_name": "mr test",
        "role_id": None,
        "disabled": False,
    }


def test_check_role_for_access(setup):
    # setup
    gatekeeper, client = setup
    global db
    db = {}
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))
    print(result)
    id = result["user_id"]

    # get token
    class Token:
        def __init__(self, username, password) -> None:
            self.username = username
            self.password = password

    tokenInput = Token("test", "test")
    result = gatekeeper.login_for_access_token(tokenInput)
    result = dict(asyncio.run(result))
    token = result["access_token"]
    result = gatekeeper.check_role_for_access(
        token=token, action="GetUser", resource=f"gatekeeper/user/{id}"
    )
    result = asyncio.run(result)
    print(result)
    assert result


def test_check_role_for_access_denied(setup):
    # setup
    gatekeeper, client = setup
    global db
    db = {}
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))
    print(result)
    # id = result["user_id"]

    # get token
    class Token:
        def __init__(self, username, password) -> None:
            self.username = username
            self.password = password

    tokenInput = Token("test", "test")
    result = gatekeeper.login_for_access_token(tokenInput)
    result = dict(asyncio.run(result))
    token = result["access_token"]
    result = gatekeeper.check_role_for_access(
        token=token, action="GetUser", resource="gatekeeper/user/awdjioawdhjkoawd"
    )
    result = asyncio.run(result)
    print(result)
    assert not result
