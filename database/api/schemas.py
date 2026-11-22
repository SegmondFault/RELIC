"""Request and response models.

Signed text fields are verified byte-for-byte, so inputs are validated and
rejected, never trimmed or normalised.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

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
    # Deliberately no identity: a challenge is bound to no account.
    purpose: Literal["login", "registration"]


class ChallengeResponse(BaseModel):
    challenge_id: UUID
    purpose: Literal["login", "registration"]
    nonce: str = Field(description="32 random bytes, lowercase hex")
    audience: str
    expires_at: datetime
    expires_at_unix_micros: int = Field(description="Signed exactly as given")


class LoginRequest(_Request):
    challenge_id: UUID
    public_key: HexKey
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


class Approval(BaseModel):
    """A first Moderator approval, signed over the ordinary decision message."""

    moderator_id: UUID
    signature: str = Field(description="Moderator's approval signature, lowercase hex")
    approved_at: datetime


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
    approvals_required: int = Field(description="2 for a Moderator registration, else 1")
    approvals: list[Approval] = Field(description="First approvals still awaiting a second Moderator")


class RegistrationDecisionRequest(_Request):
    moderator_id: UUID
    decision: Literal["approved", "rejected"]
    signature: HexSignature


class AwaitingSecondApproval(BaseModel):
    """202: the approval is stored; another active Moderator must approve too."""

    status: Literal["awaiting_second_approval"] = "awaiting_second_approval"
    approvals: list[Approval]
    approvals_required: int = 2


class RegistrationDecisionResponse(BaseModel):
    registration_request_id: UUID
    decision: Literal["approved", "rejected"]
    decided_at: datetime
    user_id: UUID | None


# ---------------------------------------------------------------------------
# Revocations
# ---------------------------------------------------------------------------

# catalogue.corpus_target_type, in enum order.
TargetType = Literal[
    "user",
    "source",
    "batch",
    "binary",
    "function",
    "fidbf",
    "bsim",
    "provenance",
    "license_assertion",
    "software_component",
    "software_release",
    "binary_component_assertion",
    "behavioural_composition",
    "classification",
    "flag",
    "flag_response",
]
RevocationStatus = Literal["pending", "approved", "rejected"]
Reason = Annotated[str, Field(min_length=1, max_length=2000), AfterValidator(_clean_text)]


class RevocationRequest(_Request):
    revocation_id: UUID = Field(description="Chosen by the Analyst; makes the request single-use")
    analyst_id: UUID = Field(description="The requesting Analyst: must be the caller")
    target_type: TargetType
    target_id: UUID
    reason: Reason
    signature: HexSignature


class RevocationDetail(BaseModel):
    """A revocation request as stored, in the shape `decide-revocation` signs."""

    revocation_id: UUID
    status: RevocationStatus
    analyst_id: UUID
    target_type: TargetType
    target_id: UUID
    reason: str
    requested_at: datetime
    request_signature: str = Field(description="Analyst's signature, lowercase hex")
    moderator_id: UUID | None
    decided_at: datetime | None
    decision_signature: str | None = Field(description="Moderator's signature, lowercase hex")
    approvals_required: int = Field(description="2 when the target is a Moderator account, else 1")
    approvals: list[Approval] = Field(description="First approvals still awaiting a second Moderator")


class RevocationDecisionRequest(_Request):
    moderator_id: UUID
    decision: Literal["approved", "rejected"]
    signature: HexSignature


class RevocationDecisionResponse(BaseModel):
    revocation_id: UUID
    decision: Literal["approved", "rejected"]
    decided_at: datetime


# ---------------------------------------------------------------------------
# Catalogue reads
#
# Signatures and keys are lowercase hex; digests are returned exactly as
# stored. NUMERIC(20,0) addresses and NUMERIC(5,4) confidences are decimal
# strings so that no client loses precision. `revoked` is true when an
# approved revocation targets this exact object (not its parents).
# ---------------------------------------------------------------------------

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Md5 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Signature = Annotated[str, Field(description="Signature bytes, lowercase hex")]
DecimalText = Annotated[str, Field(description="Exact decimal value as text")]


class Source(BaseModel):
    source_id: UUID
    name: str
    source_type: str
    reference: str | None
    snapshot_version: str | None
    retrieved_at: datetime
    is_ecological: bool | None
    submitted_by_analyst_id: UUID
    signature: Signature
    revoked: bool


class Batch(BaseModel):
    batch_id: UUID
    md5: str
    content_sha256: str
    created_at: datetime
    analyst_user_id: UUID
    signature: Signature
    revoked: bool


class Binary(BaseModel):
    binary_id: UUID
    batch_id: UUID
    source_id: UUID
    content_sha256: str
    content_md5: str
    size_bytes: int
    original_filename: str | None
    format: str | None
    architecture: str | None
    bit_width: int | None
    endianness: str | None
    platform: str | None
    abi: str | None
    object_type: str | None
    entry_point: DecimalText | None
    image_base: DecimalText | None
    build_id: str | None
    is_stripped: bool | None
    compiler: str | None
    version: str | None
    created_at: datetime
    created_by: UUID | None
    revoked: bool


class Function(BaseModel):
    function_id: UUID
    binary_id: UUID
    fidbf_id: UUID | None
    name: str | None
    full_hash: str
    specific_hash: str
    file_offset: int | None
    virtual_address: DecimalText | None
    size_bytes: int | None
    section_name: str | None
    symbol_name: str | None
    mangled_name: str | None
    demangled_name: str | None
    is_import: bool
    is_export: bool
    is_thunk: bool
    revoked: bool


class Fidbf(BaseModel):
    """FIDBF metadata. The object itself is not served yet."""

    fidbf_id: UUID
    binary_id: UUID
    source_id: UUID
    sha256: str
    md5: str
    created_at: datetime
    submitted_by_user_id: UUID
    signature: Signature
    revoked: bool


class Bsim(BaseModel):
    bsim_id: UUID
    source_id: UUID
    sha256: str
    md5: str
    created_at: datetime
    submitted_by_user_id: UUID
    signature: Signature
    revoked: bool


class BsimDetail(Bsim):
    object_data: Any


class FunctionBsim(BaseModel):
    function_bsim_id: UUID
    function_id: UUID
    binary_id: UUID
    bsim_id: UUID
    created_at: datetime


class Provenance(BaseModel):
    provenance_id: UUID
    source_id: UUID
    fidbf_id: UUID | None
    bsim_id: UUID | None
    binary_id: UUID | None
    schema_name: str | None
    schema_version: str | None
    sha256: str
    md5: str
    created_at: datetime
    submitted_by_user_id: UUID
    signature: Signature
    has_object_data: bool = Field(description="False for legacy rows stored only externally")
    revoked: bool


class ProvenanceDetail(Provenance):
    object_data: dict[str, Any] | None


class LicenseAssertion(BaseModel):
    license_assertion_id: UUID
    source_id: UUID | None
    binary_id: UUID | None
    spdx_expression: str
    basis: str
    confidence: DecimalText | None
    evidence_provenance_id: UUID | None
    created_at: datetime
    submitted_by_analyst_id: UUID
    signature: Signature
    revoked: bool


ClassificationTarget = Literal["binary", "function", "behavioural_composition"]


class Classification(BaseModel):
    classification_id: UUID
    target_type: ClassificationTarget
    target_id: UUID
    label: str
    confidence: DecimalText | None
    analyst_id: UUID
    misp_universe: str | None
    misp_uuid: UUID | None
    created_at: datetime
    signature: Signature
    revoked: bool


class ClassificationDetail(Classification):
    evidence: Any


class Flag(BaseModel):
    flag_id: UUID
    viewer_id: UUID
    target_type: TargetType
    target_id: UUID
    note: str
    created_at: datetime
    signature: Signature
    revoked: bool


class FlagResponse(BaseModel):
    flag_response_id: UUID
    flag_id: UUID
    analyst_id: UUID
    note: str
    created_at: datetime
    signature: Signature
    revoked: bool


# ---------------------------------------------------------------------------
# Flag writes
# ---------------------------------------------------------------------------

Note = Annotated[str, Field(min_length=1, max_length=2000), AfterValidator(_clean_text)]


class FlagSubmission(_Request):
    flag_id: UUID = Field(description="Chosen by the Viewer; makes the flag single-use")
    viewer_id: UUID = Field(description="The flagging Viewer: must be the caller")
    target_type: TargetType
    target_id: UUID
    note: Note
    signature: HexSignature


class FlagResponseSubmission(_Request):
    flag_response_id: UUID = Field(description="Chosen by the Analyst; makes the response single-use")
    analyst_id: UUID = Field(description="The responding Analyst: must be the caller")
    note: Note
    signature: HexSignature = Field(description="Over the flag as stored and this response")


class IntegrityEntry(BaseModel):
    integrity_id: int
    source_id: UUID
    source_type: str
    record_hash: str
    prev_hash: str | None = Field(description="NULL only for the genesis row")
    chain_hash: str
    format_version: int
    created_at: datetime
    system_uid: UUID
    system_signature: Signature


class MmrCheckpoint(BaseModel):
    mmr_checkpoint_id: int
    last_integrity_id: int
    leaf_count: int
    peaks: list[Any]
    commitment: str
    format_version: int
    created_at: datetime
    system_uid: UUID
    system_signature: Signature
