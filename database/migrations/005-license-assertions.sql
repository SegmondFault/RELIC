-- RELIC migration 005: additive, signed licensing assertions for Sources and
-- Binaries. Existing rows are neither rewritten nor backfilled.

\set ON_ERROR_STOP on

-- PostgreSQL requires a newly added enum value to be committed before it can
-- be used by functions in the following transaction.
ALTER TYPE catalogue.corpus_target_type
    ADD VALUE IF NOT EXISTS 'license_assertion';

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

CREATE TYPE license_assertion_basis AS ENUM (
    'declared',
    'detected',
    'inferred',
    'analyst_assessed'
);

CREATE TABLE license_assertion (
    license_assertion_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id uuid REFERENCES source(source_id) ON DELETE RESTRICT,
    binary_id uuid REFERENCES binary_record(binary_id) ON DELETE RESTRICT,
    spdx_expression text NOT NULL CHECK (btrim(spdx_expression) <> ''),
    basis license_assertion_basis NOT NULL,
    confidence numeric(5, 4)
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    evidence_provenance_id uuid
        REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_by_analyst_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    CHECK (num_nonnulls(source_id, binary_id) = 1)
);

COMMENT ON TABLE license_assertion IS
    'Append-only signed licensing claim about exactly one Source or Binary. Absence means not assessed; corrections are new assertions plus revocation.';
COMMENT ON COLUMN license_assertion.spdx_expression IS
    'SPDX license expression, NONE or NOASSERTION. Full SPDX validation is performed by the application before admission.';
COMMENT ON COLUMN license_assertion.evidence_provenance_id IS
    'Optional supporting cell-seal/provenance object; scanner and SPDX-list versions belong in that inspectable evidence.';

CREATE INDEX license_assertion_source_id_idx ON license_assertion(source_id)
    WHERE source_id IS NOT NULL;
CREATE INDEX license_assertion_binary_id_idx ON license_assertion(binary_id)
    WHERE binary_id IS NOT NULL;
CREATE INDEX license_assertion_evidence_idx
    ON license_assertion(evidence_provenance_id)
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
        WHEN 'classification' THEN EXISTS (
            SELECT 1 FROM classification WHERE classification_id = candidate_id
        )
        WHEN 'flag' THEN EXISTS (
            SELECT 1 FROM flag WHERE flag_id = candidate_id
        )
    END;
END;
$$;

CREATE TRIGGER license_assertion_requires_analyst
BEFORE INSERT ON license_assertion
FOR EACH ROW EXECUTE FUNCTION require_actor_role(
    'submitted_by_analyst_id', 'analyst'
);

CREATE FUNCTION reject_license_assertion_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Licence assertions are immutable; append a replacement and revoke this assertion'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER license_assertion_is_immutable
BEFORE UPDATE OR DELETE ON license_assertion
FOR EACH ROW EXECUTE FUNCTION reject_license_assertion_change();

GRANT SELECT, INSERT ON license_assertion TO relic_app;
REVOKE UPDATE, DELETE ON license_assertion FROM relic_app;

RESET ROLE;

COMMIT;
