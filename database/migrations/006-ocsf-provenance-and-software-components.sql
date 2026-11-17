-- RELIC migration 006: inline OCSF-style provenance seals and an additive,
-- signed Binary-to-software-component assertion model. Existing rows remain
-- valid and require no backfill.

\set ON_ERROR_STOP on

-- Newly added enum values must be committed before functions can use them.
ALTER TYPE catalogue.corpus_target_type
    ADD VALUE IF NOT EXISTS 'software_component';
ALTER TYPE catalogue.corpus_target_type
    ADD VALUE IF NOT EXISTS 'software_release';
ALTER TYPE catalogue.corpus_target_type
    ADD VALUE IF NOT EXISTS 'binary_component_assertion';

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

ALTER TABLE provenance
    ADD COLUMN object_data jsonb;
ALTER TABLE provenance
    ALTER COLUMN storage_path DROP NOT NULL;
ALTER TABLE provenance
    DROP CONSTRAINT IF EXISTS provenance_storage_path_check;
ALTER TABLE provenance
    ADD CONSTRAINT provenance_storage_path_check
        CHECK (storage_path IS NULL OR btrim(storage_path) <> ''),
    ADD CONSTRAINT provenance_object_or_path_check
        CHECK (num_nonnulls(storage_path, object_data) >= 1),
    ADD CONSTRAINT provenance_object_data_object_check
        CHECK (object_data IS NULL OR jsonb_typeof(object_data) = 'object');

COMMENT ON TABLE provenance IS
    'Inspectably stored OCSF-style provenance JSON, or a legacy external path, used for reproducibility verification.';
COMMENT ON COLUMN provenance.object_data IS
    'Preferred inline OCSF-style JSON seal. RELIC-specific recipe and evidence fields belong below unmapped.relic.';
COMMENT ON COLUMN provenance.storage_path IS
    'Optional legacy/external object path. New inline seals need not use a path.';

CREATE INDEX provenance_object_data_gin_idx ON provenance USING gin(object_data)
    WHERE object_data IS NOT NULL;

CREATE TYPE component_assertion_basis AS ENUM (
    'declared',
    'detected',
    'inferred',
    'analyst_assessed'
);

CREATE TYPE binary_component_relationship AS ENUM (
    'build_of',
    'statically_contains',
    'dynamically_links',
    'derived_from',
    'other'
);

CREATE TABLE software_component (
    component_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (btrim(name) <> ''),
    component_kind text NOT NULL CHECK (btrim(component_kind) <> ''),
    namespace text,
    purl text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by_analyst_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT
);

CREATE TABLE software_release (
    software_release_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id uuid NOT NULL
        REFERENCES software_component(component_id) ON DELETE RESTRICT,
    version text,
    source_id uuid REFERENCES source(source_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by_analyst_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT
);

CREATE TABLE binary_component_assertion (
    binary_component_assertion_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    binary_id uuid NOT NULL
        REFERENCES binary_record(binary_id) ON DELETE RESTRICT,
    software_release_id uuid NOT NULL
        REFERENCES software_release(software_release_id) ON DELETE RESTRICT,
    relationship binary_component_relationship NOT NULL,
    basis component_assertion_basis NOT NULL,
    confidence numeric(5, 4)
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    evidence_provenance_id uuid
        REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_by_analyst_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0)
);

COMMENT ON TABLE software_component IS
    'Immutable normalized identity such as a library, application or runtime. It is not itself a claim that a Binary contains the component.';
COMMENT ON TABLE software_release IS
    'Immutable release/version identity for a Software Component. Version and Source may be NULL when genuinely unknown.';
COMMENT ON TABLE binary_component_assertion IS
    'Append-only signed claim linking a concrete Binary to a normalized software release. Corrections are new assertions plus revocation.';

CREATE INDEX software_release_component_idx ON software_release(component_id);
CREATE INDEX software_release_source_idx ON software_release(source_id)
    WHERE source_id IS NOT NULL;
CREATE INDEX binary_component_assertion_binary_idx
    ON binary_component_assertion(binary_id);
CREATE INDEX binary_component_assertion_release_idx
    ON binary_component_assertion(software_release_id);
CREATE INDEX binary_component_assertion_evidence_idx
    ON binary_component_assertion(evidence_provenance_id)
    WHERE evidence_provenance_id IS NOT NULL;

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
        WHEN 'classification' THEN EXISTS (
            SELECT 1 FROM classification WHERE classification_id = candidate_id
        )
        WHEN 'flag' THEN EXISTS (SELECT 1 FROM flag WHERE flag_id = candidate_id)
    END;
END;
$$;

CREATE FUNCTION reject_component_model_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Software component evidence is immutable; append a replacement and revoke the superseded assertion'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER software_component_requires_analyst
BEFORE INSERT ON software_component
FOR EACH ROW EXECUTE FUNCTION require_actor_role('created_by_analyst_id', 'analyst');

CREATE TRIGGER software_release_requires_analyst
BEFORE INSERT ON software_release
FOR EACH ROW EXECUTE FUNCTION require_actor_role('created_by_analyst_id', 'analyst');

CREATE TRIGGER binary_component_assertion_requires_analyst
BEFORE INSERT ON binary_component_assertion
FOR EACH ROW EXECUTE FUNCTION require_actor_role('submitted_by_analyst_id', 'analyst');

CREATE TRIGGER software_component_is_immutable
BEFORE UPDATE OR DELETE ON software_component
FOR EACH ROW EXECUTE FUNCTION reject_component_model_change();

CREATE TRIGGER software_release_is_immutable
BEFORE UPDATE OR DELETE ON software_release
FOR EACH ROW EXECUTE FUNCTION reject_component_model_change();

CREATE TRIGGER binary_component_assertion_is_immutable
BEFORE UPDATE OR DELETE ON binary_component_assertion
FOR EACH ROW EXECUTE FUNCTION reject_component_model_change();

GRANT SELECT, INSERT ON provenance, software_component, software_release,
    binary_component_assertion TO relic_app;
REVOKE UPDATE, DELETE ON software_component, software_release,
    binary_component_assertion FROM relic_app;

RESET ROLE;

COMMIT;
