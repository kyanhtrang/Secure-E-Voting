from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


class AuthenticationDenied(Exception):
    """Invalid credentials or inactive/unregistered voter."""


class AuthenticationUnavailable(Exception):
    """A trusted authentication dependency failed."""


@dataclass(frozen=True)
class VerifiedIdentity:
    provider: str
    subject: str

    def __post_init__(self):
        if not self.provider or not self.provider.strip():
            raise ValueError("Invalid identity provider")

        if not self.subject or not self.subject.strip():
            raise ValueError("Invalid identity subject")


class CredentialVerifier(Protocol):
    def verify_credentials(
        self,
        username: str,
        password: str,
    ) -> VerifiedIdentity | None:
        ...


class VoterAccountReader(Protocol):
    def find_active_voter_id(
        self,
        provider: str,
        subject: str,
    ) -> UUID | None:
        ...


class RASessionIssuer(Protocol):
    def issue_ra_session(self, voter_id: UUID) -> str:
        ...


class RAAuthenticationService:
    def __init__(
        self,
        verifier: CredentialVerifier,
        accounts: VoterAccountReader,
        sessions: RASessionIssuer,
    ):
        self.verifier = verifier
        self.accounts = accounts
        self.sessions = sessions

    def login(self, username: str, password: str) -> str:
        if (
            not username
            or not username.strip()
            or not password
        ):
            raise AuthenticationDenied(
                "Authentication failed"
            )

        try:
            identity = self.verifier.verify_credentials(
                username,
                password,
            )

            if identity is None:
                raise AuthenticationDenied(
                    "Authentication failed"
                )

            voter_id = self.accounts.find_active_voter_id(
                identity.provider,
                identity.subject,
            )

            if voter_id is None:
                raise AuthenticationDenied(
                    "Authentication failed"
                )

            token = self.sessions.issue_ra_session(
                voter_id
            )

            if not isinstance(token, str) or not token:
                raise AuthenticationUnavailable(
                    "Authentication service unavailable"
                )

            return token

        except (AuthenticationDenied, AuthenticationUnavailable):
            raise

        except Exception as exc:
            raise AuthenticationUnavailable(
                "Authentication service unavailable"
            ) from exc