import pytest

from cr_service import redact


@pytest.fixture(autouse=True)
def _reset():
    yield
    redact.configure(())


@pytest.mark.parametrize(
    "name", ["password", "access_token", "Authorization", "x-api-key", "client_secret", "set-cookie"]
)
def test_secret_names(name):
    assert redact.is_secret(name)


@pytest.mark.parametrize("name", ["user_id", "auth_outcome", "code", "state", "path"])
def test_ordinary_names(name):
    assert not redact.is_secret(name)


def test_nested_values():
    value = {"user": {"password": "hunter2", "name": "a"}, "items": [{"token": "t"}], "count": 1}
    assert redact.redact(value) == {
        "user": {"password": "[redacted]", "name": "a"},
        "items": [{"token": "[redacted]"}],
        "count": 1,
    }


def test_extra_names():
    redact.configure(["Dataset-Signing-Salt"])
    assert redact.redact({"dataset_signing_salt": "s", "dataset": "d"}) == {
        "dataset_signing_salt": "[redacted]",
        "dataset": "d",
    }


def test_query_and_url():
    assert redact.redact_query([("code", "abc"), ("page", "2"), ("apikey", "k")]) == {
        "code": "[redacted]",
        "page": "2",
        "apikey": "[redacted]",
    }
    assert redact.redact_url("https://a.example/cb?code=abc&page=2") == "https://a.example/cb?code=[redacted]&page=2"
    assert redact.redact_url("https://a.example/cb") == "https://a.example/cb"
    assert redact.redact_url(None) is None
