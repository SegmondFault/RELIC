#!/usr/bin/env bash

set -euo pipefail

if (( EUID != 0 )); then
    echo "This migration runner must be run as root." >&2
    exit 1
fi

relic_dir="${RELIC_DIR:-/srv/relic}"
database_name="${RELIC_DATABASE:-relic}"
mmr_migration="$relic_dir/database/migrations/002-mmr-checkpoints.sql"
bsim_migration="$relic_dir/database/migrations/003-bsim-membership.sql"
mmr_uniqueness_migration="$relic_dir/database/migrations/004-mmr-leaf-count-uniqueness.sql"
license_assertion_migration="$relic_dir/database/migrations/005-license-assertions.sql"
ocsf_component_migration="$relic_dir/database/migrations/006-ocsf-provenance-and-software-components.sql"
behavioural_composition_migration="$relic_dir/database/migrations/007-behavioural-compositions.sql"
key_auth_migration="$relic_dir/database/migrations/008-key-auth-registration-and-rbac.sql"

for migration_file in \
    "$mmr_migration" \
    "$bsim_migration" \
    "$mmr_uniqueness_migration" \
    "$license_assertion_migration" \
    "$ocsf_component_migration" \
    "$behavioural_composition_migration" \
    "$key_auth_migration"; do
    if [[ ! -f "$migration_file" ]]; then
        echo "Migration file not found: $migration_file" >&2
        exit 1
    fi
done

mmr_installed="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN to_regclass('catalogue.mmr_checkpoint') IS NULL THEN 0 ELSE 1 END"
)"

if [[ "$mmr_installed" == "1" ]]; then
    echo "MMR checkpoint table is already installed."
else
    runuser -u postgres -- psql --no-psqlrc -X \
        -v ON_ERROR_STOP=1 \
        -d "$database_name" \
        -f "$mmr_migration"

    echo "Installed catalogue.mmr_checkpoint."
fi

bsim_membership_installed="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN to_regclass('catalogue.function_bsim') IS NULL THEN 0 ELSE 1 END"
)"

bsim_has_legacy_columns="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN EXISTS (
            SELECT 1
              FROM information_schema.columns
             WHERE table_schema = 'catalogue'
               AND table_name = 'bsim'
               AND column_name IN ('function_id', 'binary_id')
        ) THEN 1 ELSE 0 END"
)"

if [[ "$bsim_membership_installed" == "1" && "$bsim_has_legacy_columns" == "0" ]]; then
    echo "BSim membership normalization is already installed."
elif [[ "$bsim_membership_installed" == "0" && "$bsim_has_legacy_columns" == "1" ]]; then
    runuser -u postgres -- psql --no-psqlrc -X \
        -v ON_ERROR_STOP=1 \
        -d "$database_name" \
        -f "$bsim_migration"

    echo "Installed catalogue.function_bsim and migrated existing memberships."
else
    echo "Refusing BSim migration: database is in an unexpected partial state." >&2
    exit 1
fi

mmr_leaf_count_unique="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN EXISTS (
            SELECT 1
              FROM pg_constraint
             WHERE conrelid = 'catalogue.mmr_checkpoint'::regclass
               AND conname = 'mmr_checkpoint_format_version_leaf_count_key'
        ) THEN 1 ELSE 0 END"
)"

if [[ "$mmr_leaf_count_unique" == "1" ]]; then
    echo "MMR leaf-count uniqueness is already installed."
else
    runuser -u postgres -- psql --no-psqlrc -X \
        -v ON_ERROR_STOP=1 \
        -d "$database_name" \
        -f "$mmr_uniqueness_migration"

    echo "Installed MMR leaf-count uniqueness."
fi

license_assertions_installed="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN to_regclass('catalogue.license_assertion') IS NULL THEN 0 ELSE 1 END"
)"

if [[ "$license_assertions_installed" == "1" ]]; then
    echo "Licence assertions are already installed."
else
    runuser -u postgres -- psql --no-psqlrc -X \
        -v ON_ERROR_STOP=1 \
        -d "$database_name" \
        -f "$license_assertion_migration"

    echo "Installed catalogue.license_assertion."
fi

ocsf_components_installed="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN
            EXISTS (
                SELECT 1 FROM information_schema.columns
                 WHERE table_schema = 'catalogue'
                   AND table_name = 'provenance'
                   AND column_name = 'object_data'
            )
            AND to_regclass('catalogue.software_component') IS NOT NULL
            AND to_regclass('catalogue.software_release') IS NOT NULL
            AND to_regclass('catalogue.binary_component_assertion') IS NOT NULL
        THEN 1 ELSE 0 END"
)"

if [[ "$ocsf_components_installed" == "1" ]]; then
    echo "OCSF provenance and software-component assertions are already installed."
else
    runuser -u postgres -- psql --no-psqlrc -X \
        -v ON_ERROR_STOP=1 \
        -d "$database_name" \
        -f "$ocsf_component_migration"

    echo "Installed inline OCSF provenance and software-component assertions."
fi

behavioural_compositions_installed="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN
            to_regclass('catalogue.behavioural_composition') IS NOT NULL
            AND to_regclass('catalogue.composition_member') IS NOT NULL
        THEN 1 ELSE 0 END"
)"

if [[ "$behavioural_compositions_installed" == "1" ]]; then
    echo "Behavioural compositions are already installed."
else
    runuser -u postgres -- psql --no-psqlrc -X \
        -v ON_ERROR_STOP=1 \
        -d "$database_name" \
        -f "$behavioural_composition_migration"

    echo "Installed behavioural compositions and classification target support."
fi

key_auth_installed="$(
    runuser -u postgres -- psql --no-psqlrc -X -d "$database_name" -Atqc \
        "SELECT CASE WHEN
            to_regclass('catalogue.auth_challenge') IS NOT NULL
            AND to_regclass('catalogue.registration_request') IS NOT NULL
        THEN 1 ELSE 0 END"
)"

if [[ "$key_auth_installed" == "1" ]]; then
    echo "Key authentication, registration and RBAC hardening are already installed."
else
    runuser -u postgres -- psql --no-psqlrc -X \
        -v ON_ERROR_STOP=1 \
        -d "$database_name" \
        -f "$key_auth_migration"

    echo "Installed key authentication, pending registration and RBAC hardening."
fi
