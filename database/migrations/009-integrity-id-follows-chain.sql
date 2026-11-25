-- RELIC migration 009: integrity ids follow the chain.
--
-- An entry's MMR leaf index is its position on the integrity chain followed
-- from the genesis row through prev_hash; relic-checkpoint-mmr and
-- relic-verify read the chain that way. The API's inclusion proofs find the
-- same position by integrity_id order, which an index serves cheaply. The two
-- agreed only because every writer takes the integrity sequencer lock and
-- extends the row with the highest id; nothing enforced it, and if they ever
-- diverged every proof would fail.
--
-- This makes it a rule: an entry must extend the entry with the highest
-- integrity_id below its own, and only an entry with no lower id may be the
-- genesis. Together with integrity_single_successor_idx it holds even for a
-- writer that skips the lock: of two concurrent entries extending the same
-- row, the unique index admits one, and an entry cannot slot in below one
-- that is already committed.
--
-- Applies on top of migration 008. It refuses to install if the existing
-- chain already breaks the rule: run relic-verify and investigate first.

\set ON_ERROR_STOP on

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

DO $$
DECLARE
    first_break bigint;
BEGIN
    SELECT ordered.integrity_id
      INTO first_break
      FROM (
          SELECT integrity_id,
                 prev_hash,
                 lag(chain_hash) OVER (ORDER BY integrity_id) AS previous_hash
            FROM integrity
      ) AS ordered
     WHERE ordered.prev_hash IS DISTINCT FROM ordered.previous_hash
     ORDER BY ordered.integrity_id
     LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
            'integrity entry % does not extend the entry with the next lower integrity_id',
            first_break
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
END
$$;

CREATE FUNCTION integrity_follows_id_order()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    previous_hash sha256_hex;
BEGIN
    SELECT chain_hash
      INTO previous_hash
      FROM integrity
     WHERE integrity_id < NEW.integrity_id
     ORDER BY integrity_id DESC
     LIMIT 1;

    IF NEW.prev_hash IS DISTINCT FROM previous_hash THEN
        RAISE EXCEPTION
            'Integrity entry % must extend the entry with the highest integrity_id below it',
            NEW.integrity_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION integrity_follows_id_order() IS
    'Keeps integrity_id order equal to chain order (prev_hash links), which inclusion proofs rely on.';

CREATE TRIGGER integrity_follows_id_order
BEFORE INSERT ON integrity
FOR EACH ROW EXECUTE FUNCTION integrity_follows_id_order();

RESET ROLE;

COMMIT;
