-- RELIC restored-database verification.
--
-- Run with psql -v ON_ERROR_STOP=1 against the restored database:
--   psql -d relic_restore -f backup/scripts/sql/verify-relic-db.sql
--
-- This checks database invariants that do not require the system signing keys.
-- A full restore drill should also inspect the object directories and keys.

\set ON_ERROR_STOP on

SET search_path = catalogue, public;

DO $$
DECLARE
    total bigint;
    genesis bigint;
    broken bigint;
    checkpoints bigint;
    seq_last bigint;
    max_id bigint;
BEGIN
    IF to_regclass('catalogue.integrity') IS NULL THEN
        RAISE EXCEPTION 'catalogue.integrity is missing';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE prev_hash IS NULL)
      INTO total, genesis
      FROM catalogue.integrity;

    IF total = 0 THEN
        RAISE NOTICE 'integrity table is empty; skipping chain continuity checks';
    ELSE
        IF genesis <> 1 THEN
            RAISE EXCEPTION 'expected exactly one integrity genesis row, found %', genesis;
        END IF;

        WITH ordered AS (
            SELECT integrity_id,
                   prev_hash,
                   lag(chain_hash) OVER (ORDER BY integrity_id) AS expected
              FROM catalogue.integrity
        )
        SELECT count(*) INTO broken
          FROM ordered
         WHERE prev_hash IS DISTINCT FROM expected;

        IF broken <> 0 THEN
            RAISE EXCEPTION '% integrity row(s) have a broken prev_hash link', broken;
        END IF;
        RAISE NOTICE 'integrity chain: % rows, one genesis, no broken links', total;
    END IF;

    IF to_regclass('catalogue.mmr_checkpoint') IS NOT NULL THEN
        SELECT count(*) INTO checkpoints FROM catalogue.mmr_checkpoint;
        IF checkpoints > 0 THEN
            SELECT count(*) INTO broken
              FROM catalogue.mmr_checkpoint c
             WHERE NOT EXISTS (
                 SELECT 1 FROM catalogue.integrity i
                  WHERE i.integrity_id = c.last_integrity_id
             );
            IF broken <> 0 THEN
                RAISE EXCEPTION '% MMR checkpoint(s) reference a missing integrity row', broken;
            END IF;
        END IF;
        RAISE NOTICE 'MMR checkpoints: %', checkpoints;
    END IF;

    IF to_regclass('catalogue.integrity_integrity_id_seq') IS NOT NULL THEN
        EXECUTE 'SELECT last_value FROM catalogue.integrity_integrity_id_seq' INTO seq_last;
        SELECT coalesce(max(integrity_id), 0) INTO max_id FROM catalogue.integrity;
        IF seq_last < max_id THEN
            RAISE EXCEPTION 'integrity identity sequence is behind max integrity_id (% < %)', seq_last, max_id;
        END IF;
    END IF;

    IF to_regclass('catalogue.mmr_checkpoint_mmr_checkpoint_id_seq') IS NOT NULL THEN
        EXECUTE 'SELECT last_value FROM catalogue.mmr_checkpoint_mmr_checkpoint_id_seq' INTO seq_last;
        SELECT coalesce(max(mmr_checkpoint_id), 0) INTO max_id FROM catalogue.mmr_checkpoint;
        IF seq_last < max_id THEN
            RAISE EXCEPTION 'MMR identity sequence is behind max mmr_checkpoint_id (% < %)', seq_last, max_id;
        END IF;
    END IF;

    RAISE NOTICE 'restored RELIC database verification passed';
END;
$$;
