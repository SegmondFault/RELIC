"""Request and response models.

Signed text fields are verified byte-for-byte, so inputs are validated and
rejected, never trimmed or normalised.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

Role = Literal["viewer", "analyst", "moderator"]

_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _clean_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("must not start or end with whitespace")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in value):
        raise ValueError("must not contain control or format characters")
    return value


def _email(value: str) -> str:
    if not _EMAIL.fullmatch(value):
        raise ValueError("must be an email address")
    return value


HexKey = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", description="32-byte Ed25519 key, lowercase hex")]
HexSignature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$", description="64-byte Ed25519 signature, lowercase hex")]
DisplayText = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_clean_text)]
Email = Annotated[str, Field(min_length=3, max_length=254), AfterValidator(_clean_text), AfterValidator(_email)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChallengeRequest(_Request):
    purpose: Literal["login", "registration"]
    user_id: UUID | None = None

    @model_validator(mode="after")
    def _user_matches_purpose(self) -> ChallengeRequest:
        if (self.purpose == "login") != (self.user_id is not None):
            raise ValueError("user_id is required for login and forbidden for registration")
        return self


class ChallengeResponse(BaseModel):
    challenge_id: UUID
    purpose: Literal["login", "registration"]
    nonce: str = Field(description="32 random bytes, lowercase hex")
    audience: str
    expires_at: datetime
    expires_at_unix_micros: int = Field(description="Signed exactly as given")


class LoginRequest(_Request):
    challenge_id: UUID
    user_id: UUID
    signature: HexSignature


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class RegistrationRequest(_Request):
    challenge_id: UUID
    public_key: HexKey
    requested_role: Role
    name: DisplayText
    organisation: DisplayText | None = None
    email: Email
    signature: HexSignature


class RegistrationResponse(BaseModel):
    registration_request_id: UUID
    status: Literal["pending"] = "pending"
    requested_at: datetime


class UserPublic(BaseModel):
    user_id: UUID
    role: Role | None = Field(description="NULL for system accounts")
    owner_type: Literal["human", "system"]
    public_key: str = Field(description="Ed25519 public key, lowercase hex")
    created_at: datetime
    revoked: bool


RegistrationStatus = Literal["pending", "approved", "rejected"]


class RegistrationDetail(BaseModel):
    """A registration request as a Moderator reviews it (includes contact details)."""

    registration_request_id: UUID
    status: RegistrationStatus
    public_key: str = Field(description="Applicant's Ed25519 public key, lowercase hex")
    requested_role: Role
    name: str
    organisation: str | None
    email: str
    requested_at: datetime
    moderator_id: UUID | None
    decided_at: datetime | None
    decision_signature: str | None = Field(description="Moderator's signature, lowercase hex")
    user_id: UUID | None = Field(description="The created account, once approved")


class RegistrationDecisionRequest(_Request):
    moderator_id: UUID
    decision: Literal["approved", "rejected"]
    signature: HexSignature


class RegistrationDecisionResponse(BaseModel):
    registration_request_id: UUID
    decision: Literal["approved", "rejected"]
    decided_at: datetime
    user_id: UUID | None
