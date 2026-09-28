"""Climate Resource's WorkOS environments.

None of these values are secret: they identify an environment and authenticate nothing.
Both environments serve tokens from the custom API domain,
and each signs every application's tokens with one environment-wide key.
"""

import dataclasses
import typing

WorkOSEnvironmentName = typing.Literal["production", "staging"]

API_HOSTNAME = "auth-api.climateresource.com.au"


@dataclasses.dataclass(frozen=True, slots=True)
class WorkOSEnvironment:
    """The public identifiers and URLs of one WorkOS environment.

    Parameters
    ----------
    name
        ``production`` or ``staging``.
    root_client_id
        Client id of the environment's default application.
        User-token issuers and machine-token audiences name this id, whichever application minted the token.
    authkit_domain
        Hostname of the AuthKit sign-in UI, which also issues machine-to-machine tokens.
    api_hostname
        Hostname serving the user-management API, the user-token issuer and its JWKS.
    """

    name: WorkOSEnvironmentName
    root_client_id: str
    authkit_domain: str
    api_hostname: str = API_HOSTNAME

    @property
    def user_token_issuer(self) -> str:
        """``iss`` of access tokens minted for people signing in."""
        return f"https://{self.api_hostname}/user_management/{self.root_client_id}"

    @property
    def user_jwks_url(self) -> str:
        """JWKS holding the keys that sign user access tokens."""
        return f"https://{self.api_hostname}/sso/jwks/{self.root_client_id}"

    @property
    def machine_token_issuer(self) -> str:
        """``iss`` of client-credentials (machine-to-machine) access tokens."""
        return f"https://{self.authkit_domain}"

    @property
    def machine_jwks_url(self) -> str:
        """JWKS holding the keys that sign machine access tokens."""
        return f"{self.machine_token_issuer}/oauth2/jwks"

    @property
    def machine_token_audience(self) -> str:
        """``aud`` of machine access tokens."""
        return self.root_client_id

    @property
    def token_url(self) -> str:
        """Endpoint a machine client posts its client credentials to."""
        return f"{self.machine_token_issuer}/oauth2/token"


PRODUCTION = WorkOSEnvironment(
    name="production",
    root_client_id="client_01KABZE0SFNZXEYZ337HSVBZ36",
    authkit_domain="auth.climateresource.com.au",
)

STAGING = WorkOSEnvironment(
    name="staging",
    root_client_id="client_01KABZE0E62YS9H7BMV6YZGMD1",
    authkit_domain="balanced-universe-28-staging.authkit.app",
)

WORKOS_ENVIRONMENTS: dict[WorkOSEnvironmentName, WorkOSEnvironment] = {
    "production": PRODUCTION,
    "staging": STAGING,
}


def workos_environment_for(environment: str) -> WorkOSEnvironment:
    """Map a deployment environment to its WorkOS environment, which is staging unless it is production."""
    return PRODUCTION if environment == "production" else STAGING
