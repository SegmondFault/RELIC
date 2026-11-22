-- Transactional regression checks for RELIC admission and derived MMR state.
-- Run only against a disposable database; this file rolls back its own data.

\set ON_ERROR_STOP on

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    system_id uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
    bsim_id_value uuid := gen_random_uuid();
    rejected boolean := false;
BEGIN
    BEGIN
        INSERT INTO user_public (user_id, public_key, role, owner_type)
        VALUES
            (analyst_id, decode(repeat('01', 32), 'hex'), 'analyst', 'human'),
            (system_id, decode(repeat('02', 32), 'hex'), NULL, 'system');

        INSERT INTO source (
            source_id, name, source_type, retrieved_at,
            submitted_by_analyst_id, signature
        ) VALUES (
            source_id_value, 'atomic-rollback-source', 'BSIM', clock_timestamp(),
            analyst_id, decode(repeat('03', 64), 'hex')
        );

        INSERT INTO bsim (
            bsim_id, object_data, sha256, md5, submitted_by_user_id,
            signature, source_id
        ) VALUES (
            bsim_id_value, '{"value":1}', repeat('a', 64), repeat('b', 32),
            analyst_id, decode(repeat('04', 64), 'hex'), source_id_value
        );

        -- The trigger must reject this mismatch and the surrounding
        -- subtransaction must remove every earlier row from the attempt.
        INSERT INTO integrity (
            source_id, source_type, record_hash, prev_hash, chain_hash,
            format_version, system_signature, system_uid
        ) VALUES (
            source_id_value, 'FIDBF', repeat('c', 64), NULL, repeat('d', 64),
            1, decode(repeat('05', 64), 'hex'), system_id
        );
    EXCEPTION
        WHEN check_violation THEN
            rejected := true;
    END;

    IF NOT rejected THEN
        RAISE EXCEPTION 'invalid integrity source_type was not rejected';
    END IF;
    IF EXISTS (SELECT FROM source WHERE source_id = source_id_value)
        OR EXISTS (SELECT FROM bsim WHERE bsim_id = bsim_id_value)
        OR EXISTS (SELECT FROM user_public WHERE user_id IN (analyst_id, system_id))
    THEN
        RAISE EXCEPTION 'failed admission left partial authoritative rows';
    END IF;
END;
$$;

DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    viewer_id uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
    assertion_id uuid := gen_random_uuid();
    rejected boolean;
BEGIN
    INSERT INTO user_public (user_id, public_key, role, owner_type)
    VALUES
        (analyst_id, decode(repeat('31', 32), 'hex'), 'analyst', 'human'),
        (viewer_id, decode(repeat('32', 32), 'hex'), 'viewer', 'human');

    INSERT INTO source (
        source_id, name, source_type, retrieved_at,
        submitted_by_analyst_id, signature
    ) VALUES (
        source_id_value, 'licensing-source', 'source archive',
        clock_timestamp(), analyst_id, decode(repeat('33', 64), 'hex')
    );

    INSERT INTO license_assertion (
        license_assertion_id, source_id, spdx_expression, basis,
        submitted_by_analyst_id, signature
    ) VALUES (
        assertion_id, source_id_value, 'MIT OR Apache-2.0', 'declared',
        analyst_id, decode(repeat('34', 64), 'hex')
    );

    IF NOT target_exists('license_assertion', assertion_id) THEN
        RAISE EXCEPTION 'licence assertion is not available to revocation targets';
    END IF;

    rejected := false;
    BEGIN
        UPDATE license_assertion
           SET spdx_expression = 'MIT'
         WHERE license_assertion_id = assertion_id;
    EXCEPTION
        WHEN integrity_constraint_violation THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'licence assertion mutation was not rejected';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO license_assertion (
            source_id, binary_id, spdx_expression, basis,
            submitted_by_analyst_id, signature
        ) VALUES (
            source_id_value, gen_random_uuid(), 'MIT', 'detected',
            analyst_id, decode(repeat('35', 64), 'hex')
        );
    EXCEPTION
        WHEN check_violation OR foreign_key_violation THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'multi-target licence assertion was not rejected';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO license_assertion (
            source_id, spdx_expression, basis,
            submitted_by_analyst_id, signature
        ) VALUES (
            source_id_value, 'NOASSERTION', 'analyst_assessed',
            viewer_id, decode(repeat('36', 64), 'hex')
        );
    EXCEPTION
        WHEN insufficient_privilege THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'viewer licensing submission was not rejected';
    END IF;
END;
$$;

DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    integrity_system_id uuid := gen_random_uuid();
    mmr_system_id uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
    batch_id_value uuid := gen_random_uuid();
    binary_id_value uuid := gen_random_uuid();
    first_function_id uuid := gen_random_uuid();
    second_function_id uuid := gen_random_uuid();
    bsim_id_value uuid := gen_random_uuid();
    first_integrity_id bigint;
    second_integrity_id bigint;
    checkpoint_id bigint;
    rejected boolean;
BEGIN
    INSERT INTO user_public (user_id, public_key, role, owner_type)
    VALUES
        (analyst_id, decode(repeat('11', 32), 'hex'), 'analyst', 'human'),
        (integrity_system_id, decode(repeat('12', 32), 'hex'), NULL, 'system'),
        (mmr_system_id, decode(repeat('13', 32), 'hex'), NULL, 'system');

    INSERT INTO source (
        source_id, name, source_type, retrieved_at,
        submitted_by_analyst_id, signature
    ) VALUES (
        source_id_value, 'valid-membership-source', 'BSIM', clock_timestamp(),
        analyst_id, decode(repeat('14', 64), 'hex')
    );

    INSERT INTO batch (
        batch_id, md5, content_sha256, analyst_user_id, signature
    ) VALUES (
        batch_id_value, repeat('1', 32), repeat('2', 64), analyst_id, decode(repeat('15', 64), 'hex')
    );

    INSERT INTO binary_record (
        binary_id, batch_id, content_sha256, content_md5, size_bytes,
        created_by, source_id
    ) VALUES (
        binary_id_value, batch_id_value, repeat('3', 64), repeat('4', 32), 16,
        analyst_id, source_id_value
    );

    INSERT INTO function_record (
        function_id, binary_id, full_hash, specific_hash
    ) VALUES
        (first_function_id, binary_id_value, 'full-1', 'specific-1'),
        (second_function_id, binary_id_value, 'full-2', 'specific-2');

    INSERT INTO bsim (
        bsim_id, object_data, sha256, md5, submitted_by_user_id,
        signature, source_id
    ) VALUES (
        bsim_id_value, '{"value":2}', repeat('5', 64), repeat('6', 32),
        analyst_id, decode(repeat('16', 64), 'hex'), source_id_value
    );

    INSERT INTO function_bsim (function_id, binary_id, bsim_id)
    VALUES
        (first_function_id, binary_id_value, bsim_id_value),
        (second_function_id, binary_id_value, bsim_id_value);

    IF (SELECT count(*) FROM function_bsim WHERE bsim_id = bsim_id_value) <> 2 THEN
        RAISE EXCEPTION 'one BSim object did not retain both Function memberships';
    END IF;

    INSERT INTO integrity (
        source_id, source_type, record_hash, prev_hash, chain_hash,
        format_version, system_signature, system_uid
    ) VALUES (
        source_id_value, 'BSIM', repeat('7', 64), NULL, repeat('8', 64),
        1, decode(repeat('17', 64), 'hex'), integrity_system_id
    ) RETURNING integrity_id INTO first_integrity_id;

    INSERT INTO integrity (
        source_id, source_type, record_hash, prev_hash, chain_hash,
        format_version, system_signature, system_uid
    ) VALUES (
        source_id_value, 'BSIM', repeat('9', 64), repeat('8', 64), repeat('a', 64),
        1, decode(repeat('18', 64), 'hex'), integrity_system_id
    ) RETURNING integrity_id INTO second_integrity_id;

    rejected := false;
    BEGIN
        INSERT INTO mmr_checkpoint (
            last_integrity_id, leaf_count, peaks, commitment, format_version,
            system_uid, system_signature
        ) VALUES (
            second_integrity_id, 1, '[{"height":1}]', repeat('b', 64), 1,
            mmr_system_id, decode(repeat('19', 64), 'hex')
        );
    EXCEPTION
        WHEN check_violation THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'incorrect MMR leaf_count was not rejected';
    END IF;

    INSERT INTO mmr_checkpoint (
        last_integrity_id, leaf_count, peaks, commitment, format_version,
        system_uid, system_signature
    ) VALUES (
        second_integrity_id, 2, '[{"height":1}]', repeat('c', 64), 1,
        mmr_system_id, decode(repeat('20', 64), 'hex')
    ) RETURNING mmr_checkpoint_id INTO checkpoint_id;

    rejected := false;
    BEGIN
        UPDATE mmr_checkpoint SET commitment = repeat('d', 64)
        WHERE mmr_checkpoint_id = checkpoint_id;
    EXCEPTION
        WHEN integrity_constraint_violation THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'MMR checkpoint mutation was not rejected';
    END IF;

    IF first_integrity_id >= second_integrity_id THEN
        RAISE EXCEPTION 'integrity identity order is inconsistent';
    END IF;
END;
$$;

DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
    batch_id_value uuid := gen_random_uuid();
    binary_id_value uuid := gen_random_uuid();
    provenance_id_value uuid := gen_random_uuid();
    component_id_value uuid := gen_random_uuid();
    release_id_value uuid := gen_random_uuid();
    assertion_id_value uuid := gen_random_uuid();
    rejected boolean;
BEGIN
    INSERT INTO user_public (user_id, public_key, role, owner_type)
    VALUES (analyst_id, decode(repeat('41', 32), 'hex'), 'analyst', 'human');

    INSERT INTO source (
        source_id, name, source_type, retrieved_at, is_ecological,
        submitted_by_analyst_id, signature
    ) VALUES (
        source_id_value, 'component-test', 'BSIM', clock_timestamp(), false,
        analyst_id, decode(repeat('42', 64), 'hex')
    );
    INSERT INTO batch (
        batch_id, md5, content_sha256, analyst_user_id, signature
    ) VALUES (
        batch_id_value, repeat('1', 32), repeat('2', 64), analyst_id, decode(repeat('43', 64), 'hex')
    );
    INSERT INTO binary_record (
        binary_id, batch_id, content_sha256, content_md5, size_bytes,
        created_by, source_id
    ) VALUES (
        binary_id_value, batch_id_value, repeat('3', 64), repeat('4', 32), 1,
        analyst_id, source_id_value
    );

    INSERT INTO provenance (
        provenance_id, binary_id, schema_name, schema_version, object_data,
        sha256, md5, submitted_by_user_id, signature, source_id
    ) VALUES (
        provenance_id_value, binary_id_value, 'ocsf', '1.9.0',
        '{"class_uid":5020,"category_uid":5,"activity_id":2,"type_uid":502002,"time":1,"severity_id":1,"metadata":{"version":"1.9.0","product":{"name":"RELIC"}},"unmapped":{"relic":{"schema_version":"relic.provenance/1.0"}}}',
        repeat('5', 64), repeat('6', 32), analyst_id, decode(repeat('44', 64), 'hex'), source_id_value
    );

    INSERT INTO software_component (
        component_id, name, component_kind, purl, created_by_analyst_id
    ) VALUES (
        component_id_value, 'libexample', 'library',
        'pkg:generic/libexample@1.0', analyst_id
    );
    INSERT INTO software_release (
        software_release_id, component_id, version, source_id,
        created_by_analyst_id
    ) VALUES (
        release_id_value, component_id_value, '1.0', source_id_value, analyst_id
    );
    INSERT INTO binary_component_assertion (
        binary_component_assertion_id, binary_id, software_release_id,
        relationship, basis, confidence, evidence_provenance_id,
        submitted_by_analyst_id, signature
    ) VALUES (
        assertion_id_value, binary_id_value, release_id_value,
        'statically_contains', 'detected', 0.8750, provenance_id_value,
        analyst_id, decode(repeat('45', 64), 'hex')
    );

    IF NOT target_exists('binary_component_assertion', assertion_id_value) THEN
        RAISE EXCEPTION 'component assertion is unavailable to revocation targets';
    END IF;

    rejected := false;
    BEGIN
        UPDATE binary_component_assertion SET confidence = 1
         WHERE binary_component_assertion_id = assertion_id_value;
    EXCEPTION
        WHEN integrity_constraint_violation THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'component assertion mutation was not rejected';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO provenance (
            binary_id, schema_name, schema_version, sha256, md5,
            submitted_by_user_id, signature, source_id
        ) VALUES (
            binary_id_value, 'ocsf', '1.9.0', repeat('7', 64), repeat('8', 32),
            analyst_id, decode(repeat('46', 64), 'hex'), source_id_value
        );
    EXCEPTION
        WHEN check_violation THEN rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'pathless and objectless provenance was accepted';
    END IF;
END;
$$;

DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
    batch_id_value uuid := gen_random_uuid();
    binary_id_value uuid := gen_random_uuid();
    function_id_value uuid := gen_random_uuid();
    composition_id_value uuid := gen_random_uuid();
    rejected boolean;
BEGIN
    INSERT INTO user_public (user_id, public_key, role, owner_type)
    VALUES (analyst_id, decode(repeat('51', 32), 'hex'), 'analyst', 'human');

    INSERT INTO source (
        source_id, name, source_type, retrieved_at,
        submitted_by_analyst_id, signature
    ) VALUES (
        source_id_value, 'composition-test', 'analysis', clock_timestamp(),
        analyst_id, decode(repeat('52', 64), 'hex')
    );
    INSERT INTO batch (
        batch_id, md5, content_sha256, analyst_user_id, signature
    ) VALUES (
        batch_id_value, repeat('1', 32), repeat('2', 64), analyst_id, decode(repeat('53', 64), 'hex')
    );
    INSERT INTO binary_record (
        binary_id, batch_id, content_sha256, content_md5, size_bytes,
        created_by, source_id
    ) VALUES (
        binary_id_value, batch_id_value, repeat('3', 64), repeat('4', 32), 1,
        analyst_id, source_id_value
    );
    INSERT INTO function_record (
        function_id, binary_id, full_hash, specific_hash
    ) VALUES (
        function_id_value, binary_id_value, 'composition-full',
        'composition-specific'
    );

    INSERT INTO behavioural_composition (
        behavioural_composition_id, name, description,
        submitted_by_analyst_id, signature
    ) VALUES (
        composition_id_value, 'staged execution chain',
        'Neutral members whose ordered combination is classified separately',
        analyst_id, decode(repeat('54', 64), 'hex')
    );
    INSERT INTO composition_member (
        behavioural_composition_id, target_type, target_id,
        member_role, sequence_number
    ) VALUES
        (composition_id_value, 'binary', binary_id_value, 'loader', 0),
        (composition_id_value, 'function', function_id_value, 'payload', 1);

    INSERT INTO classification (
        target_type, target_id, label, confidence, analyst_id,
        evidence, signature
    ) VALUES (
        'behavioural_composition', composition_id_value, 'malicious', 0.9000,
        analyst_id, '{"reason":"combined execution behaviour"}', decode(repeat('55', 64), 'hex')
    );

    IF NOT target_exists('behavioural_composition', composition_id_value) THEN
        RAISE EXCEPTION 'behavioural composition is unavailable to polymorphic targets';
    END IF;
    IF EXISTS (
        SELECT 1 FROM classification
         WHERE target_type IN ('binary', 'function')
           AND target_id IN (binary_id_value, function_id_value)
    ) THEN
        RAISE EXCEPTION 'composition classification propagated to a member';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO composition_member (
            behavioural_composition_id, target_type, target_id,
            member_role, sequence_number
        ) VALUES (
            composition_id_value, 'function', function_id_value,
            'late-member', 2
        );
    EXCEPTION
        WHEN integrity_constraint_violation THEN rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'classified composition accepted a late member';
    END IF;

    rejected := false;
    BEGIN
        UPDATE behavioural_composition SET name = 'rewritten'
         WHERE behavioural_composition_id = composition_id_value;
    EXCEPTION
        WHEN integrity_constraint_violation THEN rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'behavioural composition mutation was not rejected';
    END IF;

    rejected := false;
    BEGIN
        INSERT INTO classification (
            target_type, target_id, label, analyst_id, signature
        ) VALUES (
            'behavioural_composition', gen_random_uuid(), 'malicious',
            analyst_id, decode(repeat('56', 64), 'hex')
        );
    EXCEPTION
        WHEN foreign_key_violation THEN rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'classification accepted a missing behavioural composition';
    END IF;
END;
$$;

RESET ROLE;
ROLLBACK;
