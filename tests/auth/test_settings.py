import pydantic
import pytest

from cr_service.workos import PRODUCTION, STAGING
from tests.conftest import make_settings


def test_defaults_to_staging_workos_locally():
    settings = make_settings()
    assert settings.environment == "local"
    assert settings.workos is STAGING
    assert settings.accepted_client_ids == {"client_service"}


def test_production_uses_production_workos():
    assert make_settings(environment="production").workos is PRODUCTION


def test_workos_environment_override():
    assert make_settings(workos_environment="production").workos is PRODUCTION


def test_production_refuses_staging_workos():
    with pytest.raises(pydantic.ValidationError, match="production WorkOS"):
        make_settings(environment="production", workos_environment="staging")


def test_production_refuses_shadow_mode():
    with pytest.raises(pydantic.ValidationError, match="AUTH_ENFORCE"):
        make_settings(environment="production", auth_enforce=False)


@pytest.mark.parametrize("environment", ["staging", "preview", "production"])
def test_local_provider_only_locally(environment):
    with pytest.raises(pydantic.ValidationError, match="AUTH_PROVIDER=local"):
        make_settings(environment=environment, auth_provider="local")


def test_lists_from_environment(monkeypatch):
    monkeypatch.setenv("WORKOS_ADDITIONAL_CLIENT_IDS", "client_cli, client_other")
    monkeypatch.setenv("WORKOS_ALLOWED_ORGANIZATION_IDS", '["org_a", "org_b"]')
    monkeypatch.setenv("WORKOS_MACHINE_CLIENTS", '{"client_m2m": ["things:write"]}')
    monkeypatch.setenv("AUTH_LOCAL_PERMISSIONS", "a:read,a:write")
    settings = make_settings()
    assert settings.accepted_client_ids == {"client_service", "client_cli", "client_other"}
    assert settings.workos_allowed_organization_ids == ("org_a", "org_b")
    assert settings.workos_machine_clients == {"client_m2m": ("things:write",)}
    assert settings.auth_local_permissions == ("a:read", "a:write")


def test_api_key_is_secret(monkeypatch):
    monkeypatch.setenv("WORKOS_API_KEY", "sk_test_123")
    settings = make_settings()
    assert "sk_test_123" not in repr(settings)
    assert settings.workos_api_key is not None
    assert settings.workos_api_key.get_secret_value() == "sk_test_123"


def test_public_auth_config():
    assert make_settings(environment="production").public_auth_config() == {
        "provider": "workos",
        "workos_environment": "production",
        "client_id": "client_service",
        "api_hostname": "auth-api.climateresource.com.au",
        "authkit_domain": "auth.climateresource.com.au",
    }


def test_settings_hash_by_identity():
    settings = make_settings()
    assert hash(settings) == id(settings)
