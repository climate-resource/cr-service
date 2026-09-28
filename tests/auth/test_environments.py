import pytest

from cr_service.workos import PRODUCTION, STAGING, workos_environment_for


def test_production_urls():
    assert PRODUCTION.user_token_issuer == (
        "https://auth-api.climateresource.com.au/user_management/client_01KABZE0SFNZXEYZ337HSVBZ36"
    )
    assert PRODUCTION.user_jwks_url == (
        "https://auth-api.climateresource.com.au/sso/jwks/client_01KABZE0SFNZXEYZ337HSVBZ36"
    )
    assert PRODUCTION.machine_token_issuer == "https://auth.climateresource.com.au"
    assert PRODUCTION.machine_jwks_url == "https://auth.climateresource.com.au/oauth2/jwks"
    assert PRODUCTION.token_url == "https://auth.climateresource.com.au/oauth2/token"
    assert PRODUCTION.machine_token_audience == PRODUCTION.root_client_id


def test_staging_urls():
    assert STAGING.user_token_issuer == (
        "https://auth-api.climateresource.com.au/user_management/client_01KABZE0E62YS9H7BMV6YZGMD1"
    )
    assert STAGING.machine_token_issuer == "https://balanced-universe-28-staging.authkit.app"


@pytest.mark.parametrize(
    ("environment", "expected"),
    [("production", PRODUCTION), ("staging", STAGING), ("preview", STAGING), ("local", STAGING)],
)
def test_deployment_mapping(environment, expected):
    assert workos_environment_for(environment) is expected
