import asyncio
import pymongo
import pytest

db = {}


@pytest.fixture()
def gatekeeper(monkeypatch):
    class MockClient:
        def __init__(self, conn) -> None:
            self.path = []

        def insert_one(self, input: dict):
            db[".".join(self.path)].append(input)

        def find_one(self, query=None):
            if not query:
                return db[".".join(self.path)][0]
            if query:
                data = db[".".join(self.path)]
                filted_data = []
                for x in data:
                    filted_data = []
                    for key, data in query.items():
                        if x[key] == data:
                            filted_data.append(x)
                    data = filted_data
                if len(filted_data) != 0:
                    return filted_data[0]
                else:
                    return []

        def __getitem__(self, item):
            self.path.append(item)
            db[".".join(self.path)] = []

            return self

    monkeypatch.setattr(pymongo, "MongoClient", MockClient)
    import src.gatekeeper.main as gatekeeper

    yield gatekeeper

    del gatekeeper


def test_new_user(gatekeeper):
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))
    assert {
        "username": "test",
        "email": "test@test.com",
        "full_name": "mr test",
        "disabled": False,
    } == result


def test_duplicate_user(gatekeeper):
    global db
    db = {}

    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))
    assert {
        "username": "test",
        "email": "test@test.com",
        "full_name": "mr test",
        "disabled": False,
    } == result
    result = gatekeeper.register("test", "mr test", "test@test.com", "test")
    result = dict(asyncio.run(result))
    assert {
        "username": "test",
        "email": "test@test.com",
        "full_name": "mr test",
        "disabled": False,
    } == result
