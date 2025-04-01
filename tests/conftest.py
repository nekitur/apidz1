import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app, Base, get_db
import app.main as main

class FakeRedis:
    def __init__(self):
        self.store = {}
    def set(self, key, value):
        self.store[key] = value
    def get(self, key):
        return self.store.get(key)
    def delete(self, key):
        if key in self.store:
            del self.store[key]

main.redis_client = FakeRedis()

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
connection = engine.connect()
Base.metadata.create_all(bind=connection)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=connection)

main.engine = engine
main.SessionLocal = TestingSessionLocal

@pytest.fixture()
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db

    from fastapi.testclient import TestClient
    with TestClient(app) as client:
        yield client
