-- RELIC migration 008: key-challenge authentication, pending BYO-key
-- registration and RBAC hardening.
--
-- Applies on top of relic-schema-v1.sql + relic-access-v1.sql (fresh install)
-- and on top of migration 007 (upgraded server).
--
-- * Login proves possession of a registered Ed25519 key by signing a
--   single-use server challenge. The client identifies itself by its public
--   key (unique across all accounts); no User ID or password is needed.
-- * Registrations stay pending outside user_public until an active Moderator
--   decides them. Approval is the only path for relic_app to create a human
--   account; system accounts and the first Moderator are created by the
--   database operator as relic_owner.
-- * Account role is immutable, Ed25519 keys are exactly 32 bytes and unique.
-- * Revocation requests and decisions carry 64-byte Ed25519 signatures,
--   decisions are final and timestamped by the database, a Moderator cannot
--   decide a revocation of their own account, a target has at most one open
--   request, and an already revoked target cannot be requested again.
-- * The requester must be an active Analyst when filing, not when the request
--   is decided, so revoking the requester cannot leave a request undecidable.
-- * System accounts (integrity and MMR workers) can only be revoked by the
--   database operator: revoking one stops admissions and checkpoints.
-- * FIDBF, BSim and provenance submitters must be Analysts.
-- * Signed evidence tables are no longer updatable by relic_app.
-- * Flags and flag responses carry 64-byte Ed25519 signatures, a Viewer can
--   flag a target once, revoked targets and revoked flags take no new flags
--   or responses, and flag responses can themselves be flagged and revoked.
-- * Every stored signature (corpus objects, integrity entries, MMR
--   checkpoints) must be a 64-byte Ed25519 signature.
-- * Workers get their own login, relic_worker; the API's relic_app can no
--   longer append to the integrity chain or MMR checkpoints, and inserts
--   only into the tables its routes write (new tables: read-only by default).
-- * relic_auditor: a read-only login for relic-verify.
-- * Approving a Moderator registration, and approving the revocation of a
--   Moderator account, need two different active Moderators.
-- * Foreign-key indexes used by filtered catalogue lists also cover the
--   primary key, so each cursor page is a single index range scan.

\set ON_ERROR_STOP on

BEGIN;

-- The integrity, MMR and FIDBF-admission workers get their own database login,
-- separate from the API's relic_app (see "Database logins" below). Creating a
-- role needs the superuser, so this runs before SET ROLE. It starts NOLOGIN;
-- the operator enables it with a password where workers run:
--   ALTER ROLE relic_worker LOGIN PASSWORD '...';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'relic_worker') THEN
        CREATE ROLE relic_worker NOLOGIN;
    END IF;
END
$$;
GRANT CONNECT ON DATABASE relic TO relic_worker;
ALTER ROLE relic_worker IN DATABASE relic SET search_path = catalogue, public;

-- relic-verify re-checks every stored signature and the chain; it only reads.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'relic_auditor') THEN
        CREATE ROLE relic_auditor NOLOGIN;
    END IF;
END
$$;
GRANT CONNECT ON DATABASE relic TO relic_auditor;
ALTER ROLE relic_auditor IN DATABASE relic SET search_path = catalogue, public;
ALTER ROLE relic_auditor IN DATABASE relic SET default_transaction_read_only = on;

SET ROLE relic_owner;
SET search_path = catalogue, public;

-- ---------------------------------------------------------------------------
-- Account identity
-- ---------------------------------------------------------------------------

ALTER TABLE user_public
    ADD CONSTRAINT user_public_ed25519_key_length
    CHECK (octet_length(public_key) = 32);

CREATE UNIQUE INDEX user_public_public_key_idx ON user_public (public_key);

CREATE OR REPLACE FUNCTION prevent_account_identity_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF NEW.user_id <> OLD.user_id
       OR NEW.public_key IS DISTINCT FROM OLD.public_key
       OR NEW.owner_type <> OLD.owner_type
       OR NEW.role IS DISTINCT FROM OLD.role
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'UserID, public key, owner type, role and creation time are immutable; create a new account instead'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE user_private
    ALTER COLUMN password_hash DROP NOT NULL,
    ALTER COLUMN password_salt DROP NOT NULL;

COMMENT ON COLUMN user_private.password_hash IS
    'Deprecated by migration 008: login is Ed25519 challenge-response. Retained only for legacy rows.';
COMMENT ON COLUMN user_private.password_salt IS
    'Deprecated by migration 008: login is Ed25519 challenge-response. Retained only for legacy rows.';

-- ---------------------------------------------------------------------------
-- Single-use authentication challenges
-- ---------------------------------------------------------------------------

CREATE TYPE auth_challenge_purpose AS ENUM (
    'login',
    'registration'
);

CREATE TABLE auth_challenge (
    challenge_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose auth_challenge_purpose NOT NULL,
    -- Deliberately bound to no account: issuing a challenge reveals nothing
    -- about which keys or accounts exist. The signed login record names the
    -- public key instead.
    nonce bytea NOT NULL UNIQUE CHECK (octet_length(nonce) = 32),
    audience text NOT NULL CHECK (btrim(audience) <> ''),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '10 minutes'),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

COMMENT ON TABLE auth_challenge IS
    'Server-issued single-use nonces for login and registration proof-of-possession. Signatures over them are verified by the application; the database enforces single use and expiry.';

CREATE FUNCTION guard_auth_challenge()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION 'A new challenge cannot already be consumed'
                USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := clock_timestamp();
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.expires_at < clock_timestamp() - interval '1 day'
           AND NOT EXISTS (
               SELECT 1 FROM registration_request
                WHERE challenge_id = OLD.challenge_id
           ) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'Only long-expired, unreferenced challenges may be removed'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.challenge_id <> OLD.challenge_id
       OR NEW.purpose <> OLD.purpose
       OR NEW.nonce <> OLD.nonce
       OR NEW.audience <> OLD.audience
       OR NEW.created_at <> OLD.created_at
       OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'Only consumption may change a challenge'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF OLD.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'Challenge % was already consumed', OLD.challenge_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF NEW.consumed_at IS NULL THEN
        RETURN NEW;
    END IF;

    NEW.consumed_at := clock_timestamp();
    IF NEW.consumed_at >= OLD.expires_at THEN
        RAISE EXCEPTION 'Challenge % has expired', OLD.challenge_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER auth_challenge_guard
BEFORE INSERT OR UPDATE OR DELETE ON auth_challenge
FOR EACH ROW EXECUTE FUNCTION guard_auth_challenge();

-- Bounded housekeeping callable by relic_app, which has no DELETE privilege.
-- Challenges referenced by a registration request are kept as evidence.
CREATE FUNCTION purge_expired_auth_challenges()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    removed bigint;
BEGIN
    DELETE FROM auth_challenge AS c
     WHERE c.expires_at < clock_timestamp() - interval '1 day'
       AND NOT EXISTS (
           SELECT 1 FROM registration_request AS r
            WHERE r.challenge_id = c.challenge_id
       );
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

-- ---------------------------------------------------------------------------
-- Pending BYO-key registration
-- ---------------------------------------------------------------------------

CREATE TYPE registration_decision AS ENUM (
    'approved',
    'rejected'
);

CREATE TABLE registration_request (
    registration_request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id uuid NOT NULL UNIQUE
        REFERENCES auth_challenge(challenge_id) ON DELETE RESTRICT,
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    requested_role account_role NOT NULL,
    name text NOT NULL CHECK (btrim(name) <> ''),
    organisation text CHECK (organisation IS NULL OR btrim(organisation) <> ''),
    email text NOT NULL CHECK (btrim(email) <> ''),
    proof_signature bytea NOT NULL CHECK (octet_length(proof_signature) = 64),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    moderator_id uuid REFERENCES user_public(user_id) ON DELETE RESTRICT,
    decision registration_decision,
    decided_at timestamptz,
    decision_signature bytea,
    user_id uuid UNIQUE REFERENCES user_public(user_id) ON DELETE RESTRICT,
    CHECK (
        (
            decision IS NULL
            AND moderator_id IS NULL
            AND decided_at IS NULL
            AND decision_signature IS NULL
            AND user_id IS NULL
        )
        OR
        (
            decision IS NOT NULL
            AND moderator_id IS NOT NULL
            AND decided_at IS NOT NULL
            AND octet_length(decision_signature) = 64
            AND (decision = 'approved') = (user_id IS NOT NULL)
        )
    )
);

COMMENT ON TABLE registration_request IS
    'BYO-key registration awaiting a signed Moderator decision. Pending requests are not identities and cannot sign corpus data.';

CREATE UNIQUE INDEX registration_request_open_key_idx
    ON registration_request (public_key)
    WHERE decision IS NULL;

CREATE FUNCTION guard_registration_request()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Registration requests are permanent records'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.decision IS NOT NULL THEN
            RAISE EXCEPTION 'A registration request must start pending'
                USING ERRCODE = 'check_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM user_public WHERE public_key = NEW.public_key) THEN
            RAISE EXCEPTION 'This public key is already registered'
                USING ERRCODE = 'unique_violation';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM auth_challenge
             WHERE challenge_id = NEW.challenge_id
               AND purpose = 'registration'
               AND consumed_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'Registration requires a consumed registration challenge'
                USING ERRCODE = 'check_violation';
        END IF;
        NEW.requested_at := clock_timestamp();
        RETURN NEW;
    END IF;

    IF OLD.decision IS NOT NULL THEN
        RAISE EXCEPTION 'Registration decisions are final'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF NEW.registration_request_id <> OLD.registration_request_id
       OR NEW.challenge_id <> OLD.challenge_id
       OR NEW.public_key <> OLD.public_key
       OR NEW.requested_role <> OLD.requested_role
       OR NEW.name <> OLD.name
       OR NEW.organisation IS DISTINCT FROM OLD.organisation
       OR NEW.email <> OLD.email
       OR NEW.proof_signature <> OLD.proof_signature
       OR NEW.requested_at <> OLD.requested_at THEN
        RAISE EXCEPTION 'A registration request cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF NEW.decision IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM user_public
             WHERE user_id = NEW.moderator_id
               AND owner_type = 'human'
               AND role = 'moderator'
        ) OR account_is_revoked(NEW.moderator_id) THEN
            RAISE EXCEPTION 'Registration decision requires an active Moderator'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        NEW.decided_at := clock_timestamp();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER registration_request_guard
BEFORE INSERT OR UPDATE OR DELETE ON registration_request
FOR EACH ROW EXECUTE FUNCTION guard_registration_request();

-- The only way relic_app can create a human account. The Moderator's
-- decision signature is verified by the application before this call.
CREATE FUNCTION decide_registration(
    p_registration_request_id uuid,
    p_moderator_id uuid,
    p_decision registration_decision,
    p_decision_signature bytea
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    request registration_request%ROWTYPE;
    new_user_id uuid;
BEGIN
    SELECT * INTO request
      FROM registration_request
     WHERE registration_request_id = p_registration_request_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown registration request %', p_registration_request_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF p_decision = 'approved' THEN
        new_user_id := gen_random_uuid();
        INSERT INTO user_public (user_id, public_key, role, owner_type)
        VALUES (new_user_id, request.public_key, request.requested_role, 'human');
        INSERT INTO user_private (user_id, name, organisation, email)
        VALUES (new_user_id, request.name, request.organisation, request.email);
    END IF;

    -- The row trigger validates the Moderator and finality.
    UPDATE registration_request
       SET moderator_id = p_moderator_id,
           decision = p_decision,
           decided_at = clock_timestamp(),
           decision_signature = p_decision_signature,
           user_id = new_user_id
     WHERE registration_request_id = p_registration_request_id;

    RETURN new_user_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- Revocation: final, database-timestamped, never self-decided
-- ---------------------------------------------------------------------------

ALTER TABLE revocation
    ADD CONSTRAINT revocation_request_signature_ed25519
        CHECK (octet_length(request_signature) = 64),
    ADD CONSTRAINT revocation_decision_signature_ed25519
        CHECK (decision_signature IS NULL OR octet_length(decision_signature) = 64);

-- At most one open request per target; the API reports a duplicate as 409.
CREATE UNIQUE INDEX revocation_open_target_idx
    ON revocation (target_type, target_id)
    WHERE decision IS NULL;

-- Replaces the schema v1 version, which re-checked the requester on every
-- update: a request filed by an Analyst who was revoked afterwards could then
-- never be decided, and the one-open-request rule below would block its
-- target for good. The requester is checked once, when the request is filed;
-- the deciding Moderator is checked whenever a decision is recorded.
CREATE OR REPLACE FUNCTION validate_revocation_actors()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    requester_role account_role;
    requester_owner account_owner_type;
    moderator_role account_role;
    moderator_owner account_owner_type;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT role, owner_type
          INTO requester_role, requester_owner
          FROM user_public
         WHERE user_id = NEW.analyst_request_id;

        IF NOT FOUND
           OR requester_owner <> 'human'
           OR requester_role <> 'analyst'
           OR account_is_revoked(NEW.analyst_request_id) THEN
            RAISE EXCEPTION 'Revocation requester must be an active Analyst'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    IF NEW.decision IS NOT NULL THEN
        SELECT role, owner_type
          INTO moderator_role, moderator_owner
          FROM user_public
         WHERE user_id = NEW.moderator_id;

        IF NOT FOUND
           OR moderator_owner <> 'human'
           OR moderator_role <> 'moderator'
           OR account_is_revoked(NEW.moderator_id) THEN
            RAISE EXCEPTION 'Revocation decision requires an active Moderator'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

-- relic_owner (and superusers) are the database operator.
CREATE FUNCTION is_database_operator()
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = catalogue, pg_temp
AS $$
    SELECT pg_has_role(current_user, 'relic_owner', 'USAGE');
$$;

CREATE FUNCTION guard_revocation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Revocations are permanent records'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.decision IS NOT NULL THEN
            RAISE EXCEPTION 'A revocation request must start pending'
                USING ERRCODE = 'check_violation';
        END IF;
        IF EXISTS (
            SELECT 1 FROM revocation
             WHERE target_type = NEW.target_type
               AND target_id = NEW.target_id
               AND decision = 'approved'
        ) THEN
            RAISE EXCEPTION 'Target %.% is already revoked', NEW.target_type, NEW.target_id
                USING ERRCODE = 'unique_violation';
        END IF;
        IF NEW.target_type = 'user'
           AND NOT is_database_operator()
           AND EXISTS (
               SELECT 1 FROM user_public
                WHERE user_id = NEW.target_id AND owner_type = 'system'
           ) THEN
            RAISE EXCEPTION 'System accounts can only be revoked by the database operator'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        NEW.requested_at := clock_timestamp();
        RETURN NEW;
    END IF;

    IF OLD.decision IS NOT NULL THEN
        RAISE EXCEPTION 'Revocation decisions are final'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF NEW.revocation_id <> OLD.revocation_id
       OR NEW.analyst_request_id <> OLD.analyst_request_id
       OR NEW.target_type <> OLD.target_type
       OR NEW.target_id <> OLD.target_id
       OR NEW.reason <> OLD.reason
       OR NEW.requested_at <> OLD.requested_at
       OR NEW.request_signature <> OLD.request_signature THEN
        RAISE EXCEPTION 'A revocation request cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF NEW.decision IS NOT NULL THEN
        IF NEW.target_type = 'user' AND NEW.target_id = NEW.moderator_id THEN
            RAISE EXCEPTION 'A Moderator cannot decide the revocation of their own account'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.target_type = 'user'
           AND NOT is_database_operator()
           AND EXISTS (
               SELECT 1 FROM user_public
                WHERE user_id = NEW.target_id AND owner_type = 'system'
           ) THEN
            RAISE EXCEPTION 'System accounts can only be revoked by the database operator'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        NEW.decided_at := clock_timestamp();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER revocation_is_final
BEFORE INSERT OR UPDATE OR DELETE ON revocation
FOR EACH ROW EXECUTE FUNCTION guard_revocation();

-- ---------------------------------------------------------------------------
-- Two-Moderator approval for Moderator powers
-- ---------------------------------------------------------------------------

-- One Moderator alone could otherwise approve a new Moderator (including a
-- second key of their own) and, with any Analyst account, revoke the other
-- Moderators. Approving a Moderator registration and approving the
-- revocation of a Moderator account therefore need two different, active
-- Moderators: the first approval is stored here with its signature, the
-- second is the final decision on the request row. Each Moderator signs the
-- ordinary decision message (it names the Moderator and the verdict), so the
-- approvals are re-verifiable like any decision. A single rejection is final.

CREATE FUNCTION is_active_moderator(candidate_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = catalogue, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM user_public
         WHERE user_id = candidate_id
           AND owner_type = 'human'
           AND role = 'moderator'
    ) AND NOT account_is_revoked(candidate_id);
$$;

CREATE TABLE registration_approval (
    registration_request_id uuid NOT NULL
        REFERENCES registration_request(registration_request_id) ON DELETE RESTRICT,
    moderator_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    approval_signature bytea NOT NULL CHECK (octet_length(approval_signature) = 64),
    approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (registration_request_id, moderator_id)
);

COMMENT ON TABLE registration_approval IS
    'First Moderator approval of a Moderator registration; the second Moderator decides the request.';

CREATE TABLE revocation_approval (
    revocation_id uuid NOT NULL
        REFERENCES revocation(revocation_id) ON DELETE RESTRICT,
    moderator_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    approval_signature bytea NOT NULL CHECK (octet_length(approval_signature) = 64),
    approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (revocation_id, moderator_id)
);

COMMENT ON TABLE revocation_approval IS
    'First Moderator approval of revoking a Moderator account; a second Moderator decides the request.';

CREATE FUNCTION target_is_moderator(candidate_type corpus_target_type, candidate_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = catalogue, pg_temp
AS $$
    SELECT candidate_type = 'user' AND EXISTS (
        SELECT 1 FROM user_public WHERE user_id = candidate_id AND role = 'moderator'
    );
$$;

CREATE FUNCTION guard_registration_approval()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'Approvals are permanent records'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT is_active_moderator(NEW.moderator_id) THEN
        RAISE EXCEPTION 'An approval requires an active Moderator'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM registration_request
         WHERE registration_request_id = NEW.registration_request_id
           AND decision IS NULL
           AND requested_role = 'moderator'
    ) THEN
        RAISE EXCEPTION 'Only a pending Moderator registration takes a first approval'
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.approved_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER registration_approval_rules
BEFORE INSERT OR UPDATE OR DELETE ON registration_approval
FOR EACH ROW EXECUTE FUNCTION guard_registration_approval();

CREATE FUNCTION guard_revocation_approval()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'Approvals are permanent records'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT is_active_moderator(NEW.moderator_id) THEN
        RAISE EXCEPTION 'An approval requires an active Moderator'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM revocation
         WHERE revocation_id = NEW.revocation_id
           AND decision IS NULL
           AND target_is_moderator(target_type, target_id)
           AND target_id <> NEW.moderator_id
    ) THEN
        RAISE EXCEPTION 'Only a pending revocation of another Moderator takes a first approval'
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.approved_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER revocation_approval_rules
BEFORE INSERT OR UPDATE OR DELETE ON revocation_approval
FOR EACH ROW EXECUTE FUNCTION guard_revocation_approval();

-- Also applies through decide_registration(), which runs as relic_owner:
-- there is no operator exception for registrations (the operator creates
-- Moderators directly, see local-dev.sh bootstrap-moderator).
CREATE FUNCTION require_second_registration_approval()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF OLD.decision IS NULL
       AND NEW.decision = 'approved'
       AND NEW.requested_role = 'moderator'
       AND NOT EXISTS (
           SELECT 1 FROM registration_approval
            WHERE registration_request_id = NEW.registration_request_id
              AND moderator_id <> NEW.moderator_id
              AND is_active_moderator(moderator_id)
       ) THEN
        RAISE EXCEPTION 'Approving a Moderator needs a prior approval by another active Moderator'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER registration_moderator_needs_two
BEFORE UPDATE ON registration_request
FOR EACH ROW EXECUTE FUNCTION require_second_registration_approval();

-- The database operator may still decide alone (e.g. with only two
-- Moderators, one of them the target), as for system accounts.
CREATE FUNCTION require_second_revocation_approval()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF OLD.decision IS NULL
       AND NEW.decision = 'approved'
       AND target_is_moderator(NEW.target_type, NEW.target_id)
       AND NOT is_database_operator()
       AND NOT EXISTS (
           SELECT 1 FROM revocation_approval
            WHERE revocation_id = NEW.revocation_id
              AND moderator_id <> NEW.moderator_id
              AND moderator_id <> NEW.target_id
              AND is_active_moderator(moderator_id)
       ) THEN
        RAISE EXCEPTION 'Revoking a Moderator needs a prior approval by another active Moderator'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER revocation_moderator_needs_two
BEFORE UPDATE ON revocation
FOR EACH ROW EXECUTE FUNCTION require_second_revocation_approval();

-- ---------------------------------------------------------------------------
-- Flags and flag responses
-- ---------------------------------------------------------------------------

-- A flag response becomes a target, so an abusive response can be flagged
-- and revoked like any other object. A new enum value can only be used after
-- the transaction that adds it commits; nothing in this migration uses it.
ALTER TYPE corpus_target_type ADD VALUE IF NOT EXISTS 'flag_response';

-- Replaces the schema v1 version: adds flag_response.
CREATE OR REPLACE FUNCTION target_exists(
    candidate_type corpus_target_type,
    candidate_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    RETURN CASE candidate_type
        WHEN 'user' THEN EXISTS (
            SELECT 1 FROM user_public WHERE user_id = candidate_id
        )
        WHEN 'source' THEN EXISTS (
            SELECT 1 FROM source WHERE source_id = candidate_id
        )
        WHEN 'batch' THEN EXISTS (
            SELECT 1 FROM batch WHERE batch_id = candidate_id
        )
        WHEN 'binary' THEN EXISTS (
            SELECT 1 FROM binary_record WHERE binary_id = candidate_id
        )
        WHEN 'function' THEN EXISTS (
            SELECT 1 FROM function_record WHERE function_id = candidate_id
        )
        WHEN 'fidbf' THEN EXISTS (
            SELECT 1 FROM fidbf WHERE fidbf_id = candidate_id
        )
        WHEN 'bsim' THEN EXISTS (
            SELECT 1 FROM bsim WHERE bsim_id = candidate_id
        )
        WHEN 'provenance' THEN EXISTS (
            SELECT 1 FROM provenance WHERE provenance_id = candidate_id
        )
        WHEN 'license_assertion' THEN EXISTS (
            SELECT 1 FROM license_assertion
             WHERE license_assertion_id = candidate_id
        )
        WHEN 'software_component' THEN EXISTS (
            SELECT 1 FROM software_component WHERE component_id = candidate_id
        )
        WHEN 'software_release' THEN EXISTS (
            SELECT 1 FROM software_release
             WHERE software_release_id = candidate_id
        )
        WHEN 'binary_component_assertion' THEN EXISTS (
            SELECT 1 FROM binary_component_assertion
             WHERE binary_component_assertion_id = candidate_id
        )
        WHEN 'behavioural_composition' THEN EXISTS (
            SELECT 1 FROM behavioural_composition
             WHERE behavioural_composition_id = candidate_id
        )
        WHEN 'classification' THEN EXISTS (
            SELECT 1 FROM classification WHERE classification_id = candidate_id
        )
        WHEN 'flag' THEN EXISTS (
            SELECT 1 FROM flag WHERE flag_id = candidate_id
        )
        WHEN 'flag_response' THEN EXISTS (
            SELECT 1 FROM flag_response WHERE flag_response_id = candidate_id
        )
    END;
END;
$$;

ALTER TABLE flag
    ADD CONSTRAINT flag_signature_ed25519 CHECK (octet_length(signature) = 64);
ALTER TABLE flag_response
    ADD CONSTRAINT flag_response_signature_ed25519 CHECK (octet_length(signature) = 64);

-- One flag per Viewer per target; follow-ups belong in responses or a
-- revocation request. The API reports a second flag as 409.
CREATE UNIQUE INDEX flag_one_per_viewer_target_idx
    ON flag (viewer_request_id, target_type, target_id);

CREATE FUNCTION target_is_revoked(
    candidate_type corpus_target_type,
    candidate_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = catalogue, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM revocation
         WHERE target_type = candidate_type
           AND target_id = candidate_id
           AND decision = 'approved'
    );
$$;

-- A revoked target or flag leaves nothing to act on, so it takes no new flags
-- or responses. created_at comes from the database clock, never the client.
CREATE FUNCTION guard_flag()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF target_is_revoked(NEW.target_type, NEW.target_id) THEN
        RAISE EXCEPTION 'Target %.% is revoked', NEW.target_type, NEW.target_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_flag_response()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF target_is_revoked('flag', NEW.flag_id) THEN
        RAISE EXCEPTION 'Flag % is revoked', NEW.flag_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END;
$$;

-- Named to fire after the role and existence checks (triggers run in name order).
CREATE TRIGGER flag_target_not_revoked
BEFORE INSERT ON flag
FOR EACH ROW EXECUTE FUNCTION guard_flag();

CREATE TRIGGER flag_response_target_not_revoked
BEFORE INSERT ON flag_response
FOR EACH ROW EXECUTE FUNCTION guard_flag_response();

-- ---------------------------------------------------------------------------
-- Analyst-only corpus objects
-- ---------------------------------------------------------------------------

DROP TRIGGER fidbf_requires_active_submitter ON fidbf;
DROP TRIGGER bsim_requires_active_submitter ON bsim;
DROP TRIGGER provenance_requires_active_submitter ON provenance;

CREATE TRIGGER fidbf_requires_analyst
BEFORE INSERT OR UPDATE ON fidbf
FOR EACH ROW EXECUTE FUNCTION require_actor_role('submitted_by_user_id', 'analyst');

CREATE TRIGGER bsim_requires_analyst
BEFORE INSERT OR UPDATE ON bsim
FOR EACH ROW EXECUTE FUNCTION require_actor_role('submitted_by_user_id', 'analyst');

CREATE TRIGGER provenance_requires_analyst
BEFORE INSERT OR UPDATE ON provenance
FOR EACH ROW EXECUTE FUNCTION require_actor_role('submitted_by_user_id', 'analyst');

-- ---------------------------------------------------------------------------
-- Catalogue read paging
-- ---------------------------------------------------------------------------

-- Filtered lists run WHERE <filter> = $1 AND <pk> > $cursor ORDER BY <pk>.
-- With an index on <filter> alone, PostgreSQL either sorts every matching row
-- for each page or walks the primary key and skips non-matching rows, which
-- can read most of the table. An index on (<filter>, <pk>) serves each page
-- as one range scan. It still serves foreign-key and equality lookups on
-- <filter>, so it replaces the single-column index under the same name.
-- Near-unique hash filters (sha256, md5) keep their single-column indexes.

DROP INDEX binary_batch_id_idx;
CREATE INDEX binary_batch_id_idx ON binary_record (batch_id, binary_id);
DROP INDEX binary_source_id_idx;
CREATE INDEX binary_source_id_idx ON binary_record (source_id, binary_id);

DROP INDEX fidbf_binary_id_idx;
CREATE INDEX fidbf_binary_id_idx ON fidbf (binary_id, fidbf_id);
DROP INDEX fidbf_source_id_idx;
CREATE INDEX fidbf_source_id_idx ON fidbf (source_id, fidbf_id);

DROP INDEX function_binary_id_idx;
CREATE INDEX function_binary_id_idx ON function_record (binary_id, function_id);
DROP INDEX function_fidbf_id_idx;
CREATE INDEX function_fidbf_id_idx ON function_record (fidbf_id, function_id);

DROP INDEX bsim_source_id_idx;
CREATE INDEX bsim_source_id_idx ON bsim (source_id, bsim_id);

-- function_id lookups use UNIQUE (function_id, bsim_id); a function has few links.
DROP INDEX function_bsim_binary_id_idx;
CREATE INDEX function_bsim_binary_id_idx ON function_bsim (binary_id, function_bsim_id);
DROP INDEX function_bsim_bsim_id_idx;
CREATE INDEX function_bsim_bsim_id_idx ON function_bsim (bsim_id, function_bsim_id);

DROP INDEX provenance_source_id_idx;
CREATE INDEX provenance_source_id_idx ON provenance (source_id, provenance_id);
DROP INDEX provenance_fidbf_id_idx;
CREATE INDEX provenance_fidbf_id_idx ON provenance (fidbf_id, provenance_id);
DROP INDEX provenance_bsim_id_idx;
CREATE INDEX provenance_bsim_id_idx ON provenance (bsim_id, provenance_id);
DROP INDEX provenance_binary_id_idx;
CREATE INDEX provenance_binary_id_idx ON provenance (binary_id, provenance_id);

DROP INDEX license_assertion_source_id_idx;
CREATE INDEX license_assertion_source_id_idx
    ON license_assertion (source_id, license_assertion_id)
    WHERE source_id IS NOT NULL;
DROP INDEX license_assertion_binary_id_idx;
CREATE INDEX license_assertion_binary_id_idx
    ON license_assertion (binary_id, license_assertion_id)
    WHERE binary_id IS NOT NULL;

DROP INDEX classification_target_idx;
CREATE INDEX classification_target_idx
    ON classification (target_type, target_id, classification_id);

DROP INDEX flag_target_idx;
CREATE INDEX flag_target_idx ON flag (target_type, target_id, flag_id);
DROP INDEX flag_response_flag_id_idx;
CREATE INDEX flag_response_flag_id_idx ON flag_response (flag_id, flag_response_id);

DROP INDEX integrity_source_id_idx;
CREATE INDEX integrity_source_id_idx ON integrity (source_id, integrity_id);

-- ---------------------------------------------------------------------------
-- Signed evidence: Ed25519 signatures only
-- ---------------------------------------------------------------------------

-- Schema v1 only required these to be non-empty. Every signature RELIC stores
-- is a 64-byte Ed25519 signature; anything else is malformed.
ALTER TABLE source ADD CONSTRAINT source_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE batch ADD CONSTRAINT batch_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE fidbf ADD CONSTRAINT fidbf_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE bsim ADD CONSTRAINT bsim_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE provenance ADD CONSTRAINT provenance_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE license_assertion ADD CONSTRAINT license_assertion_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE binary_component_assertion ADD CONSTRAINT binary_component_assertion_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE behavioural_composition ADD CONSTRAINT behavioural_composition_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE classification ADD CONSTRAINT classification_signature_ed25519
    CHECK (octet_length(signature) = 64);
ALTER TABLE integrity ADD CONSTRAINT integrity_system_signature_ed25519
    CHECK (octet_length(system_signature) = 64);
ALTER TABLE mmr_checkpoint ADD CONSTRAINT mmr_checkpoint_system_signature_ed25519
    CHECK (octet_length(system_signature) = 64);

-- ---------------------------------------------------------------------------
-- Application privileges
-- ---------------------------------------------------------------------------

-- Signed evidence is append-only for the application.
REVOKE UPDATE ON
    source,
    batch,
    binary_record,
    fidbf,
    function_record,
    bsim,
    function_bsim,
    provenance,
    classification,
    flag,
    flag_response,
    integrity
FROM relic_app;

-- Identities are created only through decide_registration(), which runs as
-- relic_owner. Contact details reach Moderators through registration_request;
-- no route reads or writes user_private, so a compromised API cannot dump or
-- rewrite them.
REVOKE INSERT, UPDATE ON user_public FROM relic_app;
REVOKE SELECT, INSERT, UPDATE ON user_private FROM relic_app;

GRANT SELECT, INSERT, UPDATE ON auth_challenge TO relic_app;
GRANT SELECT, INSERT ON registration_request TO relic_app;
GRANT SELECT, INSERT ON registration_approval, revocation_approval TO relic_app;
REVOKE UPDATE, DELETE ON registration_approval, revocation_approval FROM relic_app;
REVOKE UPDATE, DELETE ON registration_request FROM relic_app;

REVOKE EXECUTE ON FUNCTION decide_registration(uuid, uuid, registration_decision, bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION purge_expired_auth_challenges() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION decide_registration(uuid, uuid, registration_decision, bytea) TO relic_app;
GRANT EXECUTE ON FUNCTION purge_expired_auth_challenges() TO relic_app;

-- ---------------------------------------------------------------------------
-- Database logins
-- ---------------------------------------------------------------------------
--
-- relic_owner   NOLOGIN. Owns the schema; migrations and operator actions
--               (first Moderator, system accounts, revoking a system
--               account) run as it.
-- relic_app     The API. Never signs: it verifies user signatures and
--               stores user-signed rows.
-- relic_worker  The integrity, MMR and FIDBF-admission workers. The only
--               login that appends to the integrity chain and MMR
--               checkpoints, which carry system signatures made with keys
--               the API never holds.
-- relic_auditor relic-verify (e.g. from cron). Reads everything it
--               re-verifies, writes nothing, and never sees user_private.
--
-- The database checks who a system row names, not its signature, so a
-- compromised API could otherwise append forged entries in a system
-- account's name to a chain that can never be edited.

REVOKE INSERT ON integrity, mmr_checkpoint FROM relic_app;

-- relic_app inserts only what its routes write: challenges, registration
-- requests, revocations, first approvals, flags and flag responses. Each
-- submission route grants its own table when it is implemented, so a
-- compromised API cannot write rows no route needs (some of which have no
-- signed format relic-verify could check yet), and new tables are not
-- writable by the API unless a migration says so.
REVOKE INSERT ON
    source, batch, binary_record, fidbf, function_record, bsim, function_bsim,
    provenance, license_assertion, software_component, software_release,
    binary_component_assertion, behavioural_composition, composition_member,
    classification
FROM relic_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA catalogue REVOKE INSERT, UPDATE ON TABLES FROM relic_app;

GRANT USAGE ON SCHEMA catalogue TO relic_worker;

-- Row triggers run with the caller's privileges, so admission must be able to
-- read what they check. Contact details, registration requests and login
-- challenges are not catalogue data and stay out of reach.
GRANT SELECT ON
    source, batch, binary_record, fidbf, function_record, bsim, function_bsim,
    provenance, license_assertion, software_component, software_release,
    binary_component_assertion, behavioural_composition, composition_member,
    classification, flag, flag_response, revocation, user_public,
    integrity, mmr_checkpoint
TO relic_worker;

-- relic-ingest-fidbf admits a source, batch, binary, FIDBF and functions with
-- one integrity entry; relic-chain-bsim appends integrity entries;
-- relic-checkpoint-mmr appends checkpoints. Append-only: no UPDATE or DELETE.
GRANT INSERT ON
    source, batch, binary_record, fidbf, function_record, integrity, mmr_checkpoint
TO relic_worker;

-- Registration proofs are signed over their challenge and decisions over the
-- request's contact details, so the auditor reads those tables too.
GRANT USAGE ON SCHEMA catalogue TO relic_auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA catalogue TO relic_auditor;
REVOKE SELECT ON user_private FROM relic_auditor;

RESET ROLE;

COMMIT;
