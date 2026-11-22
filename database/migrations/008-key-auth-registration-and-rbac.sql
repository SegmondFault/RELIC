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
-- * Revocation decisions are final, timestamped by the database, and a
--   Moderator cannot decide a revocation of their own account.
-- * FIDBF, BSim and provenance submitters must be Analysts.
-- * Signed evidence tables are no longer updatable by relic_app.

\set ON_ERROR_STOP on

BEGIN;

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
        NEW.decided_at := clock_timestamp();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER revocation_is_final
BEFORE INSERT OR UPDATE OR DELETE ON revocation
FOR EACH ROW EXECUTE FUNCTION guard_revocation();

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

-- Identities are created only through decide_registration().
REVOKE INSERT, UPDATE ON user_public FROM relic_app;
REVOKE INSERT ON user_private FROM relic_app;

GRANT SELECT, INSERT, UPDATE ON auth_challenge TO relic_app;
GRANT SELECT, INSERT ON registration_request TO relic_app;
REVOKE UPDATE, DELETE ON registration_request FROM relic_app;

REVOKE EXECUTE ON FUNCTION decide_registration(uuid, uuid, registration_decision, bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION purge_expired_auth_challenges() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION decide_registration(uuid, uuid, registration_decision, bytea) TO relic_app;
GRANT EXECUTE ON FUNCTION purge_expired_auth_challenges() TO relic_app;

RESET ROLE;

COMMIT;
