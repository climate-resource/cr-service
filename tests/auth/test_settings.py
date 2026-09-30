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


def test_production_shadow_opt_in():
    settings = make_settings(environment="production", auth_enforce=False, auth_allow_production_shadow=True)
    assert not settings.auth_enforce


@pytest.mark.parametrize("environment", ["staging", "preview", "production"])
@pytest.mark.parametrize("provider", ["local", "fake"])
def test_local_providers_only_locally(environment, provider):
    with pytest.raises(pydantic.ValidationError, match=f"AUTH_PROVIDER={provider}"):
        make_settings(environment=environment, auth_provider=provider)


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


@pytest.mark.parametrize(("environment", "workos"), [("staging", STAGING), ("production", PRODUCTION)])
def test_accept_bookshelf_tokens(environment, workos):
    settings = make_settings(environment=environment, workos_accept_bookshelf_tokens=True)
    assert settings.accepted_client_ids == {"client_service", workos.bookshelf_client_id}


def test_bookshelf_tokens_refused_by_default():
    assert STAGING.bookshelf_client_id not in make_settings().accepted_client_ids


def test_machine_client_organizations_need_known_clients():
    with pytest.raises(pydantic.ValidationError, match="client_unknown"):
        make_settings(workos_machine_client_organizations={"client_unknown": ["org_a"]})
    with pytest.raises(pydantic.ValidationError, match="no organisations"):
        make_settings(
            workos_machine_clients={"client_m2m": []}, workos_machine_client_organizations={"client_m2m": []}
        )


def test_accepting_api_keys_needs_the_management_key():
    with pytest.raises(pydantic.ValidationError, match="WORKOS_ACCEPT_API_KEYS"):
        make_settings(workos_accept_api_keys=True)
    assert make_settings(workos_accept_api_keys=True, workos_api_key="sk_test").workos_accept_api_keys


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
