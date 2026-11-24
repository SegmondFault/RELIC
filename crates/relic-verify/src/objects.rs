//! `BSim` objects and provenance seals: each is signed by its Analyst over its
//! exact JSON text (by digest) and, for `BSim`, its function links, and each
//! has its own integrity-chain entry.

use std::collections::{HashMap, HashSet};

use postgres::Transaction;
use relic_crypto::sha256;
use relic_ingest::objects::{
    BSIM_SIGNATURE_DOMAIN, FunctionLink, PROVENANCE_SIGNATURE_DOMAIN, bsim_record, object_digests,
    provenance_record,
};
use relic_integrity_worker::{
    BsimRecord, ProvenanceRecord, bsim_record_hash, provenance_record_hash,
};
use uuid::Uuid;

use crate::{Accounts, Chain, Report, check_signature, micros};

pub(crate) fn bsim(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    chain: &Chain,
    explained: &mut HashSet<i64>,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let mut links: HashMap<Uuid, Vec<FunctionLink>> = HashMap::new();
    for row in tx.query(
        "SELECT bsim_id, function_id, binary_id FROM catalogue.function_bsim",
        &[],
    )? {
        links.entry(row.get(0)).or_default().push(FunctionLink {
            function_id: row.get(1),
            binary_id: row.get(2),
        });
    }
    let rows = tx.query(
        "SELECT bsim_id, source_id, sha256::text, md5::text, created_at, submitted_by_user_id,
                signature, object_json
           FROM catalogue.bsim",
        &[],
    )?;
    for row in &rows {
        let bsim_id: Uuid = row.get(0);
        let source_id: Uuid = row.get(1);
        let sha256_hex: String = row.get(2);
        let md5_hex: String = row.get(3);
        let submitter: Uuid = row.get(5);
        let signature: Vec<u8> = row.get(6);
        let object_json: String = row.get(7);
        let id = bsim_id.to_string();
        if object_digests(&object_json) != (sha256_hex.clone(), md5_hex.clone()) {
            report.fail("BSim object", &id, "stored digests do not match its object");
        }
        let record = bsim_record(
            bsim_id,
            submitter,
            source_id,
            &sha256_hex,
            &md5_hex,
            links.get(&bsim_id).map_or(&[][..], Vec::as_slice),
        );
        if check_signature(
            report,
            accounts,
            "BSim object",
            &id,
            submitter,
            "analyst",
            BSIM_SIGNATURE_DOMAIN,
            &sha256(&record),
            &signature,
        ) {
            report.checked("BSim objects");
        }
        let entry = bsim_record_hash(&BsimRecord {
            bsim_id,
            source_id,
            sha256: &sha256_hex,
            md5: &md5_hex,
            created_at_micros: micros(row.get(4)),
            submitter,
            signature: &signature,
        });
        match chain.find(source_id, &entry.to_string(), None) {
            Some(integrity_id) => {
                explained.insert(integrity_id);
                report.checked("BSim chain entries");
            }
            None => report.warn("BSim object", bsim_id, "not yet in the integrity chain"),
        }
    }
    Ok(())
}

pub(crate) fn provenance(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    chain: &Chain,
    explained: &mut HashSet<i64>,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    // Seals stored only as an external path (legacy) have no signed format.
    let rows = tx.query(
        "SELECT provenance_id, source_id, fidbf_id, bsim_id, binary_id, schema_name,
                schema_version, sha256::text, md5::text, created_at, submitted_by_user_id,
                signature, object_json
           FROM catalogue.provenance
          WHERE object_json IS NOT NULL",
        &[],
    )?;
    for row in &rows {
        let provenance_id: Uuid = row.get(0);
        let source_id: Uuid = row.get(1);
        let schema_name: Option<String> = row.get(5);
        let schema_version: Option<String> = row.get(6);
        let sha256_hex: String = row.get(7);
        let md5_hex: String = row.get(8);
        let submitter: Uuid = row.get(10);
        let signature: Vec<u8> = row.get(11);
        let object_json: String = row.get(12);
        let id = provenance_id.to_string();
        if object_digests(&object_json) != (sha256_hex.clone(), md5_hex.clone()) {
            report.fail("provenance", &id, "stored digests do not match its seal");
        }
        let record = provenance_record(
            provenance_id,
            submitter,
            source_id,
            row.get(2),
            row.get(3),
            row.get(4),
            schema_name.as_deref(),
            schema_version.as_deref(),
            &sha256_hex,
            &md5_hex,
        );
        if check_signature(
            report,
            accounts,
            "provenance",
            &id,
            submitter,
            "analyst",
            PROVENANCE_SIGNATURE_DOMAIN,
            &sha256(&record),
            &signature,
        ) {
            report.checked("provenance seals");
        }
        let entry = provenance_record_hash(&ProvenanceRecord {
            provenance_id,
            source_id,
            sha256: &sha256_hex,
            md5: &md5_hex,
            created_at_micros: micros(row.get(9)),
            submitter,
            signature: &signature,
        });
        match chain.find(source_id, &entry.to_string(), None) {
            Some(integrity_id) => {
                explained.insert(integrity_id);
                report.checked("provenance chain entries");
            }
            None => report.warn(
                "provenance",
                provenance_id,
                "not yet in the integrity chain",
            ),
        }
    }
    Ok(())
}
