-- RELIC migration 007: immutable analyst-defined behavioural compositions.
-- A classification may target a composition without propagating its label to
-- any individual Binary or Function member.

\set ON_ERROR_STOP on

-- PostgreSQL requires a newly added enum value to be committed before it is
-- referenced by constraints, functions or rows.
ALTER TYPE catalogue.corpus_target_type
    ADD VALUE IF NOT EXISTS 'behavioural_composition';

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

CREATE TABLE behavioural_composition (
    behavioural_composition_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (btrim(name) <> ''),
    description text,
    evidence_provenance_id uuid
        REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_by_analyst_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0)
);

COMMENT ON TABLE behavioural_composition IS
    'Immutable analyst-defined set or sequence whose combined behaviour may be classified without propagating that classification to its members.';

CREATE TABLE composition_member (
    composition_member_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    behavioural_composition_id uuid NOT NULL
        REFERENCES behavioural_composition(behavioural_composition_id)
        ON DELETE RESTRICT,
    target_type corpus_target_type NOT NULL
        CHECK (target_type IN ('binary', 'function')),
    target_id uuid NOT NULL,
    member_role text NOT NULL CHECK (btrim(member_role) <> ''),
    sequence_number integer CHECK (
        sequence_number IS NULL OR sequence_number >= 0
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE NULLS NOT DISTINCT (
        behavioural_composition_id,
        target_type,
        target_id,
        member_role,
        sequence_number
    )
);

COMMENT ON TABLE composition_member IS
    'Immutable membership linking a Behavioural Composition to exact Binary or Function records. sequence_number is NULL when ordering is not asserted.';

ALTER TABLE classification
    DROP CONSTRAINT classification_target_type_check,
    ADD CONSTRAINT classification_target_type_check CHECK (
        target_type IN ('binary', 'function', 'behavioural_composition')
    );

CREATE INDEX behavioural_composition_evidence_idx
    ON behavioural_composition(evidence_provenance_id)
    WHERE evidence_provenance_id IS NOT NULL;
CREATE INDEX composition_member_composition_idx
    ON composition_member(behavioural_composition_id);
CREATE INDEX composition_member_target_idx
    ON composition_member(target_type, target_id);

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
        WHEN 'user' THEN EXISTS (SELECT 1 FROM user_public WHERE user_id = candidate_id)
        WHEN 'source' THEN EXISTS (SELECT 1 FROM source WHERE source_id = candidate_id)
        WHEN 'batch' THEN EXISTS (SELECT 1 FROM batch WHERE batch_id = candidate_id)
        WHEN 'binary' THEN EXISTS (SELECT 1 FROM binary_record WHERE binary_id = candidate_id)
        WHEN 'function' THEN EXISTS (SELECT 1 FROM function_record WHERE function_id = candidate_id)
        WHEN 'fidbf' THEN EXISTS (SELECT 1 FROM fidbf WHERE fidbf_id = candidate_id)
        WHEN 'bsim' THEN EXISTS (SELECT 1 FROM bsim WHERE bsim_id = candidate_id)
        WHEN 'provenance' THEN EXISTS (SELECT 1 FROM provenance WHERE provenance_id = candidate_id)
        WHEN 'license_assertion' THEN EXISTS (
            SELECT 1 FROM license_assertion WHERE license_assertion_id = candidate_id
        )
        WHEN 'software_component' THEN EXISTS (
            SELECT 1 FROM software_component WHERE component_id = candidate_id
        )
        WHEN 'software_release' THEN EXISTS (
            SELECT 1 FROM software_release WHERE software_release_id = candidate_id
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
        WHEN 'flag' THEN EXISTS (SELECT 1 FROM flag WHERE flag_id = candidate_id)
    END;
END;
$$;

CREATE FUNCTION reject_behavioural_composition_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Behavioural compositions and their membership are immutable; append a replacement and revoke the superseded composition'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE FUNCTION reject_member_after_composition_classification()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM classification
         WHERE target_type = 'behavioural_composition'
           AND target_id = NEW.behavioural_composition_id
    ) THEN
        RAISE EXCEPTION 'A classified Behavioural Composition cannot gain members; create a replacement composition'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER behavioural_composition_requires_analyst
BEFORE INSERT ON behavioural_composition
FOR EACH ROW EXECUTE FUNCTION require_actor_role(
    'submitted_by_analyst_id', 'analyst'
);

CREATE TRIGGER composition_member_target_must_exist
BEFORE INSERT OR UPDATE OF target_type, target_id ON composition_member
FOR EACH ROW EXECUTE FUNCTION validate_polymorphic_target();

CREATE TRIGGER composition_member_precedes_classification
BEFORE INSERT ON composition_member
FOR EACH ROW EXECUTE FUNCTION reject_member_after_composition_classification();

CREATE TRIGGER behavioural_composition_is_immutable
BEFORE UPDATE OR DELETE ON behavioural_composition
FOR EACH ROW EXECUTE FUNCTION reject_behavioural_composition_change();

CREATE TRIGGER composition_member_is_immutable
BEFORE UPDATE OR DELETE ON composition_member
FOR EACH ROW EXECUTE FUNCTION reject_behavioural_composition_change();

GRANT SELECT, INSERT ON behavioural_composition, composition_member TO relic_app;
REVOKE UPDATE, DELETE ON behavioural_composition, composition_member FROM relic_app;

RESET ROLE;

COMMIT;
