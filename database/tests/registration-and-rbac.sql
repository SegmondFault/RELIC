-- Regression checks for migration 008 (key auth, registration, RBAC).
-- Run only against a disposable database as a superuser; everything rolls back.

\set ON_ERROR_STOP on

BEGIN;

SET search_path = catalogue, public;

CREATE TEMP TABLE t (name text PRIMARY KEY, id uuid NOT NULL) ON COMMIT DROP;
GRANT ALL ON t TO relic_app, relic_owner;

-- Owner-created fixtures: the operator bootstraps moderators and analysts.
SET ROLE relic_owner;
DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    viewer_id uuid := gen_random_uuid();
    moderator_a uuid := gen_random_uuid();
    moderator_b uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
BEGIN
    INSERT INTO user_public (user_id, public_key, role, owner_type) VALUES
        (analyst_id, decode(repeat('a1', 32), 'hex'), 'analyst', 'human'),
        (viewer_id, decode(repeat('a2', 32), 'hex'), 'viewer', 'human'),
        (moderator_a, decode(repeat('a3', 32), 'hex'), 'moderator', 'human'),
        (moderator_b, decode(repeat('a4', 32), 'hex'), 'moderator', 'human');

    INSERT INTO source (
        source_id, name, source_type, retrieved_at, submitted_by_analyst_id, signature
    ) VALUES (
        source_id_value, 'rbac-test-source', 'BSIM', clock_timestamp(), analyst_id, '\x01'
    );

    INSERT INTO pg_temp.t VALUES
        ('analyst', analyst_id), ('viewer', viewer_id),
        ('moderator_a', moderator_a), ('moderator_b', moderator_b),
        ('source', source_id_value);
END
$$;

-- Identity invariants, enforced even for the owner.
DO $$
DECLARE
    rejected boolean;
BEGIN
    rejected := false;
    BEGIN
        UPDATE user_public SET role = 'moderator'
         WHERE user_id = (SELECT id FROM pg_temp.t WHERE name = 'viewer');
    EXCEPTION WHEN integrity_constraint_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'role escalation by UPDATE was not rejected';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO user_public (public_key, role) VALUES ('\x0102', 'viewer');
    EXCEPTION WHEN check_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'non-32-byte public key was not rejected';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO user_public (public_key, role)
        VALUES (decode(repeat('a1', 32), 'hex'), 'viewer');
    EXCEPTION WHEN unique_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'duplicate public key was not rejected';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO bsim (
            object_data, sha256, md5, submitted_by_user_id, signature, source_id
        ) VALUES (
            '{"v":1}', repeat('a', 64), repeat('b', 32),
            (SELECT id FROM pg_temp.t WHERE name = 'viewer'), '\x01',
            (SELECT id FROM pg_temp.t WHERE name = 'source')
        );
    EXCEPTION WHEN insufficient_privilege THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'viewer BSim submission was not rejected';
    END IF;
END
$$;
RESET ROLE;

-- Application privileges and the registration lifecycle, as relic_app.
SET ROLE relic_app;
DO $$
DECLARE
    rejected boolean;
    challenge uuid;
    second_challenge uuid;
    request uuid;
    new_user uuid;
    granted_role account_role;
BEGIN
    rejected := false;
    BEGIN
        INSERT INTO user_public (public_key, role)
        VALUES (decode(repeat('b1', 32), 'hex'), 'moderator');
    EXCEPTION WHEN insufficient_privilege THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'relic_app could create an account directly';
    END IF;

    rejected := false;
    BEGIN
        UPDATE source SET name = 'rewritten'
         WHERE source_id = (SELECT id FROM pg_temp.t WHERE name = 'source');
    EXCEPTION WHEN insufficient_privilege THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'relic_app could update signed evidence';
    END IF;

    INSERT INTO auth_challenge (purpose, nonce, audience, expires_at)
    VALUES ('registration', gen_random_bytes(32), 'https://relic.test',
            clock_timestamp() + interval '5 minutes')
    RETURNING challenge_id INTO challenge;

    rejected := false;
    BEGIN
        INSERT INTO registration_request (
            challenge_id, public_key, requested_role, name, email, proof_signature
        ) VALUES (
            challenge, decode(repeat('c1', 32), 'hex'), 'analyst', 'A', 'a@example.org',
            decode(repeat('00', 64), 'hex')
        );
    EXCEPTION WHEN check_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'registration with an unconsumed challenge was not rejected';
    END IF;

    UPDATE auth_challenge SET consumed_at = clock_timestamp()
     WHERE challenge_id = challenge;

    rejected := false;
    BEGIN
        UPDATE auth_challenge SET consumed_at = clock_timestamp()
         WHERE challenge_id = challenge;
    EXCEPTION WHEN integrity_constraint_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'challenge was consumed twice';
    END IF;

    INSERT INTO registration_request (
        challenge_id, public_key, requested_role, name, email, proof_signature
    ) VALUES (
        challenge, decode(repeat('c1', 32), 'hex'), 'analyst', 'A', 'a@example.org',
        decode(repeat('00', 64), 'hex')
    ) RETURNING registration_request_id INTO request;

    INSERT INTO auth_challenge (purpose, nonce, audience, expires_at)
    VALUES ('registration', gen_random_bytes(32), 'https://relic.test',
            clock_timestamp() + interval '5 minutes')
    RETURNING challenge_id INTO second_challenge;
    UPDATE auth_challenge SET consumed_at = clock_timestamp()
     WHERE challenge_id = second_challenge;

    rejected := false;
    BEGIN
        INSERT INTO registration_request (
            challenge_id, public_key, requested_role, name, email, proof_signature
        ) VALUES (
            second_challenge, decode(repeat('c1', 32), 'hex'), 'viewer', 'B',
            'b@example.org', decode(repeat('00', 64), 'hex')
        );
    EXCEPTION WHEN unique_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'second pending request for one key was not rejected';
    END IF;

    rejected := false;
    BEGIN
        UPDATE registration_request SET requested_role = 'moderator'
         WHERE registration_request_id = request;
    EXCEPTION WHEN insufficient_privilege THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'relic_app could alter a registration request';
    END IF;

    rejected := false;
    BEGIN
        PERFORM decide_registration(
            request, (SELECT id FROM pg_temp.t WHERE name = 'viewer'),
            'approved', decode(repeat('00', 64), 'hex')
        );
    EXCEPTION WHEN insufficient_privilege THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'non-moderator registration decision was not rejected';
    END IF;

    new_user := decide_registration(
        request, (SELECT id FROM pg_temp.t WHERE name = 'moderator_a'),
        'approved', decode(repeat('00', 64), 'hex')
    );
    SELECT role INTO granted_role FROM user_public WHERE user_id = new_user;
    IF granted_role IS DISTINCT FROM 'analyst' THEN
        RAISE EXCEPTION 'approval did not create the requested analyst account';
    END IF;

    rejected := false;
    BEGIN
        PERFORM decide_registration(
            request, (SELECT id FROM pg_temp.t WHERE name = 'moderator_b'),
            'rejected', decode(repeat('00', 64), 'hex')
        );
    EXCEPTION WHEN integrity_constraint_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'registration decision was not final';
    END IF;
END
$$;

-- Revocation finality and no self-decision.
DO $$
DECLARE
    rejected boolean;
    rev_id uuid;
    moderator_a uuid := (SELECT id FROM pg_temp.t WHERE name = 'moderator_a');
    moderator_b uuid := (SELECT id FROM pg_temp.t WHERE name = 'moderator_b');
    analyst uuid := (SELECT id FROM pg_temp.t WHERE name = 'analyst');
BEGIN
    rejected := false;
    BEGIN
        INSERT INTO revocation (
            analyst_request_id, moderator_id, target_type, target_id, reason,
            decision, decided_at, request_signature, decision_signature
        ) VALUES (
            analyst, moderator_b, 'user', moderator_a, 'pre-decided',
            'approved', clock_timestamp(), '\x01', '\x02'
        );
    EXCEPTION WHEN check_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'pre-decided revocation was not rejected';
    END IF;

    INSERT INTO revocation (
        analyst_request_id, target_type, target_id, reason, request_signature
    ) VALUES (
        analyst, 'user', moderator_a, 'test', '\x01'
    ) RETURNING revocation_id INTO rev_id;

    rejected := false;
    BEGIN
        UPDATE revocation
           SET moderator_id = moderator_a, decision = 'rejected',
               decided_at = clock_timestamp(), decision_signature = '\x02'
         WHERE revocation_id = rev_id;
    EXCEPTION WHEN insufficient_privilege THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'moderator decided their own revocation';
    END IF;

    UPDATE revocation
       SET moderator_id = moderator_b, decision = 'approved',
           decided_at = '2000-01-01', decision_signature = '\x02'
     WHERE revocation_id = rev_id;

    IF (SELECT decided_at FROM revocation WHERE revocation_id = rev_id)
       < clock_timestamp() - interval '1 minute' THEN
        RAISE EXCEPTION 'revocation decision was backdated';
    END IF;

    rejected := false;
    BEGIN
        UPDATE revocation SET decision = 'rejected' WHERE revocation_id = rev_id;
    EXCEPTION WHEN integrity_constraint_violation THEN
        rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'approved revocation was reversed';
    END IF;

    IF NOT account_is_revoked(moderator_a) THEN
        RAISE EXCEPTION 'approved account revocation is not effective';
    END IF;
END
$$;
RESET ROLE;

ROLLBACK;

\echo 'registration-and-rbac: all checks passed'
