"""Request and response models.

Signed text fields are verified byte-for-byte, so inputs are validated and
rejected, never trimmed or normalised.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from .spdx import SpdxError, validate as validate_spdx

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
    revocation_id: UUID = Field(description="Chosen by the requester; makes the request single-use")
    requester_id: UUID = Field(
        description="The caller: an Analyst for a catalogue entry, a Moderator for an account"
    )
    target_type: TargetType
    target_id: UUID
    reason: Reason
    signature: HexSignature


class RevocationDetail(BaseModel):
    """A revocation request as stored, in the shape `decide-revocation` signs."""

    revocation_id: UUID
    status: RevocationStatus
    requester_id: UUID
    target_type: TargetType
    target_id: UUID
    reason: str
    requested_at: datetime
    request_signature: str = Field(description="The requester's signature, lowercase hex")
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
    object_json: str = Field(description="The object exactly as signed")


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
    object_json: str | None = Field(description="The seal exactly as signed (absent for legacy paths)")


class LicenseAssertion(BaseModel):
    license_assertion_id: UUID
    target_type: Literal["source", "binary"]
    target_id: UUID
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
    evidence_json: str | None = Field(description="The evidence exactly as signed")


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


# ---------------------------------------------------------------------------
# Licence assertions and classifications (signed by Analysts)
# ---------------------------------------------------------------------------


def _spdx(value: str) -> str:
    try:
        return validate_spdx(value)
    except SpdxError as error:
        raise ValueError(f"not an SPDX license expression: {error}") from error


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)


MAX_EVIDENCE_DEPTH = 32


def _evidence(value: str) -> str:
    def no_constant(name: str) -> None:
        raise ValueError(f"{name} is not JSON")

    try:
        parsed = json.loads(value, object_pairs_hook=_duplicate_keys, parse_constant=no_constant)
    except RecursionError as error:
        raise ValueError("nested too deeply") from error
    except ValueError as error:
        raise ValueError(f"must be a JSON object ({error})") from error
    if not isinstance(parsed, dict):
        raise ValueError("must be a JSON object")
    # Iterative walk: bounded depth, and no NUL (PostgreSQL jsonb cannot store it).
    stack: list[tuple[Any, int]] = [(parsed, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_EVIDENCE_DEPTH:
            raise ValueError(f"nested deeper than {MAX_EVIDENCE_DEPTH} levels")
        if isinstance(item, str) and "\x00" in item:
            raise ValueError("must not contain NUL characters")
        if isinstance(item, dict):
            stack.extend((key, depth) for key in item)
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


Confidence = Annotated[
    str,
    Field(
        pattern=r"^(0\.[0-9]{4}|1\.0000)$",
        description="Exactly four decimals, 0.0000 to 1.0000 (signed as written)",
    ),
]
SpdxExpression = Annotated[
    str, Field(min_length=1, max_length=1000), AfterValidator(_clean_text), AfterValidator(_spdx)
]
EvidenceJson = Annotated[
    str,
    Field(min_length=2, max_length=32_768, description="A JSON object, signed and stored verbatim"),
    AfterValidator(_evidence),
]


class LicenseAssertionSubmission(_Request):
    license_assertion_id: UUID = Field(description="Chosen by the Analyst; makes the claim single-use")
    analyst_id: UUID = Field(description="The asserting Analyst: must be the caller")
    target_type: Literal["source", "binary"]
    target_id: UUID
    spdx_expression: SpdxExpression
    basis: Literal["declared", "detected", "inferred", "analyst_assessed"]
    confidence: Confidence | None = None
    evidence_provenance_id: UUID | None = None
    signature: HexSignature


class ClassificationSubmission(_Request):
    classification_id: UUID = Field(description="Chosen by the Analyst; makes the label single-use")
    analyst_id: UUID = Field(description="The classifying Analyst: must be the caller")
    target_type: ClassificationTarget
    target_id: UUID
    label: DisplayText
    confidence: Confidence | None = None
    misp_universe: DisplayText | None = None
    misp_uuid: UUID | None = None
    evidence_json: EvidenceJson | None = None
    signature: HexSignature

    @model_validator(mode="after")
    def _misp_pair(self) -> "ClassificationSubmission":
        if (self.misp_universe is None) != (self.misp_uuid is None):
            raise ValueError("misp_universe and misp_uuid are given together or not at all")
        return self


# ---------------------------------------------------------------------------
# Software components, releases, component assertions, compositions
# ---------------------------------------------------------------------------

_PURL = re.compile(r"pkg:[a-z][a-z0-9.+-]*/\S+")


def _purl(value: str) -> str:
    if not _PURL.fullmatch(value):
        raise ValueError("must be a package URL (pkg:<type>/<name>...)")
    return value


Purl = Annotated[
    str, Field(min_length=7, max_length=1000), AfterValidator(_clean_text), AfterValidator(_purl)
]
ShortText = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_clean_text)]
Description = Annotated[str, Field(min_length=1, max_length=4000), AfterValidator(_clean_text)]
ComponentBasis = Literal["declared", "detected", "inferred", "analyst_assessed"]
ComponentRelationship = Literal[
    "build_of", "statically_contains", "dynamically_links", "derived_from", "other"
]
MemberType = Literal["binary", "function"]
MAX_COMPOSITION_MEMBERS = 500


class SoftwareComponentSubmission(_Request):
    component_id: UUID = Field(description="Chosen by the Analyst; makes the row single-use")
    analyst_id: UUID = Field(description="The creating Analyst: must be the caller")
    name: DisplayText
    component_kind: ShortText = Field(description="e.g. library, application, runtime")
    namespace: DisplayText | None = None
    purl: Purl | None = None
    signature: HexSignature


class SoftwareComponent(BaseModel):
    component_id: UUID
    name: str
    component_kind: str
    namespace: str | None
    purl: str | None
    created_at: datetime
    created_by_analyst_id: UUID
    signature: Signature
    revoked: bool


class SoftwareReleaseSubmission(_Request):
    software_release_id: UUID = Field(description="Chosen by the Analyst; makes the row single-use")
    analyst_id: UUID = Field(description="The creating Analyst: must be the caller")
    component_id: UUID
    version: DisplayText | None = Field(None, description="Omit when genuinely unknown")
    source_id: UUID | None = None
    signature: HexSignature


class SoftwareRelease(BaseModel):
    software_release_id: UUID
    component_id: UUID
    version: str | None
    source_id: UUID | None
    created_at: datetime
    created_by_analyst_id: UUID
    signature: Signature
    revoked: bool
    ancestor_revoked: bool = Field(
        description="A row this one depends on (component, release, source, binary, "
        "member or evidence) is revoked; this row itself is unchanged"
    )


class BinaryComponentAssertionSubmission(_Request):
    binary_component_assertion_id: UUID = Field(
        description="Chosen by the Analyst; makes the claim single-use"
    )
    analyst_id: UUID = Field(description="The asserting Analyst: must be the caller")
    binary_id: UUID
    software_release_id: UUID
    relationship: ComponentRelationship
    basis: ComponentBasis
    confidence: Confidence | None = None
    evidence_provenance_id: UUID | None = None
    signature: HexSignature


class BinaryComponentAssertion(BaseModel):
    binary_component_assertion_id: UUID
    binary_id: UUID
    software_release_id: UUID
    relationship: ComponentRelationship
    basis: ComponentBasis
    confidence: DecimalText | None
    evidence_provenance_id: UUID | None
    created_at: datetime
    submitted_by_analyst_id: UUID
    signature: Signature
    revoked: bool
    ancestor_revoked: bool = Field(
        description="A row this one depends on (component, release, source, binary, "
        "member or evidence) is revoked; this row itself is unchanged"
    )


class CompositionMemberIn(_Request):
    target_type: MemberType
    target_id: UUID
    member_role: ShortText
    sequence_number: int | None = Field(None, ge=0, le=2**31 - 1)


class BehaviouralCompositionSubmission(_Request):
    behavioural_composition_id: UUID = Field(
        description="Chosen by the Analyst; makes the composition single-use"
    )
    analyst_id: UUID = Field(description="The composing Analyst: must be the caller")
    name: DisplayText
    description: Description | None = None
    evidence_provenance_id: UUID | None = None
    members: list[CompositionMemberIn] = Field(
        min_length=1,
        max_length=MAX_COMPOSITION_MEMBERS,
        description="Signed together with the composition, in any order",
    )
    signature: HexSignature

    @model_validator(mode="after")
    def _distinct_members(self) -> "BehaviouralCompositionSubmission":
        keys = [
            (m.target_type, m.target_id, m.member_role, m.sequence_number) for m in self.members
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("members must be distinct")
        positions = [m.sequence_number for m in self.members if m.sequence_number is not None]
        if len(positions) != len(set(positions)):
            raise ValueError("each sequence_number may be used once")
        return self


class CompositionMember(BaseModel):
    target_type: MemberType
    target_id: UUID
    member_role: str
    sequence_number: int | None


class BehaviouralComposition(BaseModel):
    behavioural_composition_id: UUID
    name: str
    description: str | None
    evidence_provenance_id: UUID | None
    member_count: int
    created_at: datetime
    submitted_by_analyst_id: UUID
    signature: Signature
    revoked: bool
    ancestor_revoked: bool = Field(
        description="A row this one depends on (component, release, source, binary, "
        "member or evidence) is revoked; this row itself is unchanged"
    )


class BehaviouralCompositionDetail(BehaviouralComposition):
    members: list[CompositionMember] = Field(
        description="Ordered by sequence number (unordered members last), then target"
    )


# ---------------------------------------------------------------------------
# Staged submissions: FIDBF, BSim, provenance
# ---------------------------------------------------------------------------

MAX_OBJECT_JSON_BYTES = 2 * 1024 * 1024
MAX_BSIM_FUNCTIONS = 10_000
SubmissionKind = Literal["fidbf", "bsim", "provenance"]
SubmissionState = Literal["pending", "admitted", "rejected"]

def _object_bytes(value: str) -> str:
    if len(value.encode("utf-8")) > MAX_OBJECT_JSON_BYTES:
        raise ValueError(f"larger than {MAX_OBJECT_JSON_BYTES} bytes")
    return value


ObjectJson = Annotated[
    str,
    Field(min_length=2, max_length=MAX_OBJECT_JSON_BYTES,
          description="A JSON object, signed and stored as this exact text"),
    AfterValidator(_object_bytes),
    AfterValidator(_evidence),
]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Md5Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


class StagedObject(BaseModel):
    sha256: str
    md5: str
    size_bytes: int


class SubmissionStatus(BaseModel):
    submission_id: UUID = Field(description="The ID of the object it creates")
    kind: SubmissionKind
    status: SubmissionState
    received_at: datetime
    decided_at: datetime | None
    attempts: int
    result: dict[str, Any] | None = Field(description="IDs and digests, once admitted")
    error: str | None = Field(description="Why it was rejected")
    status_url: str


class _FidbfPart(BaseModel):
    fidbf_id: UUID
    storage_path: str
    sha256: Sha256Hex
    md5: Md5Hex


class _SourcePart(BaseModel):
    source_type: str


class FidbfManifest(BaseModel):
    """The parts of a signed FIDBF manifest (from relic-sign-fidbf) the API checks.

    relic-admit parses and verifies the whole manifest, signatures included.
    """

    model_config = ConfigDict(extra="allow")
    analyst_user_id: UUID
    source: _SourcePart
    fidbf: _FidbfPart
    analyst_signatures: dict[str, HexSignature]


class FunctionLinkIn(_Request):
    function_id: UUID
    binary_id: UUID


class BsimSubmissionIn(_Request):
    bsim_id: UUID = Field(description="Chosen by the Analyst; also the submission ID")
    analyst_id: UUID = Field(description="The submitting Analyst: must be the caller")
    source_id: UUID
    object_json: ObjectJson
    functions: list[FunctionLinkIn] = Field(min_length=1, max_length=MAX_BSIM_FUNCTIONS)
    signature: HexSignature

    @model_validator(mode="after")
    def _distinct_links(self) -> "BsimSubmissionIn":
        links = [(f.function_id, f.binary_id) for f in self.functions]
        if len(links) != len(set(links)):
            raise ValueError("function links must be distinct")
        return self


class ProvenanceSubmissionIn(_Request):
    provenance_id: UUID = Field(description="Chosen by the Analyst; also the submission ID")
    analyst_id: UUID = Field(description="The submitting Analyst: must be the caller")
    source_id: UUID
    fidbf_id: UUID | None = None
    bsim_id: UUID | None = None
    binary_id: UUID | None = None
    schema_name: DisplayText | None = None
    schema_version: DisplayText | None = None
    object_json: ObjectJson
    signature: HexSignature

    @model_validator(mode="after")
    def _has_target(self) -> "ProvenanceSubmissionIn":
        if self.fidbf_id is None and self.bsim_id is None and self.binary_id is None:
            raise ValueError("name a fidbf_id, bsim_id or binary_id")
        return self
