//! Software components, releases, binary-component assertions and
//! behavioural compositions: every row is signed by the Analyst who wrote it.

use std::collections::HashMap;

use postgres::Transaction;
use relic_crypto::auth;
use uuid::Uuid;

use crate::{Accounts, Report, check_signature};

pub(crate) fn verify(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    software_components(tx, accounts, report)?;
    software_releases(tx, accounts, report)?;
    binary_component_assertions(tx, accounts, report)?;
    behavioural_compositions(tx, accounts, report)
}

fn software_components(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let rows = tx.query(
        "SELECT component_id, name, component_kind, namespace, purl, created_by_analyst_id,
                signature
           FROM catalogue.software_component",
        &[],
    )?;
    for row in &rows {
        let id: Uuid = row.get(0);
        let name: String = row.get(1);
        let kind: String = row.get(2);
        let namespace: Option<String> = row.get(3);
        let purl: Option<String> = row.get(4);
        let analyst: Uuid = row.get(5);
        let signature: Vec<u8> = row.get(6);
        let component = auth::SoftwareComponent {
            component_id: id.as_bytes(),
            analyst_id: analyst.as_bytes(),
            name: &name,
            component_kind: &kind,
            namespace: namespace.as_deref(),
            purl: purl.as_deref(),
        };
        if check_signature(
            report,
            accounts,
            "software component",
            &id.to_string(),
            analyst,
            "analyst",
            auth::SOFTWARE_COMPONENT_SIGNATURE_DOMAIN,
            &auth::software_component_digest(&component),
            &signature,
        ) {
            report.checked("software components");
        }
    }
    Ok(())
}

fn software_releases(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let rows = tx.query(
        "SELECT software_release_id, component_id, version, source_id, created_by_analyst_id,
                signature
           FROM catalogue.software_release",
        &[],
    )?;
    for row in &rows {
        let id: Uuid = row.get(0);
        let component: Uuid = row.get(1);
        let version: Option<String> = row.get(2);
        let source: Option<Uuid> = row.get(3);
        let analyst: Uuid = row.get(4);
        let signature: Vec<u8> = row.get(5);
        let release = auth::SoftwareRelease {
            software_release_id: id.as_bytes(),
            analyst_id: analyst.as_bytes(),
            component_id: component.as_bytes(),
            version: version.as_deref(),
            source_id: source.as_ref().map(Uuid::as_bytes),
        };
        if check_signature(
            report,
            accounts,
            "software release",
            &id.to_string(),
            analyst,
            "analyst",
            auth::SOFTWARE_RELEASE_SIGNATURE_DOMAIN,
            &auth::software_release_digest(&release),
            &signature,
        ) {
            report.checked("software releases");
        }
    }
    Ok(())
}

fn binary_component_assertions(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let rows = tx.query(
        "SELECT binary_component_assertion_id, binary_id, software_release_id,
                relationship::text, basis::text, confidence::text, evidence_provenance_id,
                submitted_by_analyst_id, signature
           FROM catalogue.binary_component_assertion",
        &[],
    )?;
    for row in &rows {
        let id: Uuid = row.get(0);
        let binary: Uuid = row.get(1);
        let release: Uuid = row.get(2);
        let relationship: String = row.get(3);
        let basis: String = row.get(4);
        let confidence: Option<String> = row.get(5);
        let evidence: Option<Uuid> = row.get(6);
        let analyst: Uuid = row.get(7);
        let signature: Vec<u8> = row.get(8);
        let assertion = auth::BinaryComponentAssertion {
            binary_component_assertion_id: id.as_bytes(),
            analyst_id: analyst.as_bytes(),
            binary_id: binary.as_bytes(),
            software_release_id: release.as_bytes(),
            relationship: &relationship,
            basis: &basis,
            confidence: confidence.as_deref(),
            evidence_provenance_id: evidence.as_ref().map(Uuid::as_bytes),
        };
        if check_signature(
            report,
            accounts,
            "binary-component assertion",
            &id.to_string(),
            analyst,
            "analyst",
            auth::BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN,
            &auth::binary_component_assertion_digest(&assertion),
            &signature,
        ) {
            report.checked("binary-component assertions");
        }
    }
    Ok(())
}

struct StoredMember {
    target_type: String,
    target_id: Uuid,
    member_role: String,
    sequence_number: Option<i32>,
}

fn behavioural_compositions(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let mut members: HashMap<Uuid, Vec<StoredMember>> = HashMap::new();
    for row in tx.query(
        "SELECT behavioural_composition_id, target_type::text, target_id, member_role,
                sequence_number
           FROM catalogue.composition_member",
        &[],
    )? {
        members.entry(row.get(0)).or_default().push(StoredMember {
            target_type: row.get(1),
            target_id: row.get(2),
            member_role: row.get(3),
            sequence_number: row.get(4),
        });
    }
    let rows = tx.query(
        "SELECT behavioural_composition_id, name, description, evidence_provenance_id,
                member_count, submitted_by_analyst_id, signature
           FROM catalogue.behavioural_composition",
        &[],
    )?;
    for row in &rows {
        let id: Uuid = row.get(0);
        let name: String = row.get(1);
        let description: Option<String> = row.get(2);
        let evidence: Option<Uuid> = row.get(3);
        let member_count: i32 = row.get(4);
        let analyst: Uuid = row.get(5);
        let signature: Vec<u8> = row.get(6);
        let stored = members.remove(&id).unwrap_or_default();
        if usize::try_from(member_count).ok() != Some(stored.len()) {
            report.fail(
                "behavioural composition",
                id,
                format!("states {member_count} members but has {}", stored.len()),
            );
        }
        let Some(signed): Option<Vec<auth::CompositionMember<'_>>> = stored
            .iter()
            .map(|member| {
                let sequence_number = match member.sequence_number {
                    None => Some(None),
                    Some(value) => u32::try_from(value).ok().map(Some),
                }?;
                Some(auth::CompositionMember {
                    target_type: &member.target_type,
                    target_id: member.target_id.as_bytes(),
                    member_role: &member.member_role,
                    sequence_number,
                })
            })
            .collect()
        else {
            report.fail(
                "behavioural composition",
                id,
                "a member has a negative sequence number",
            );
            continue;
        };
        let composition = auth::BehaviouralComposition {
            behavioural_composition_id: id.as_bytes(),
            analyst_id: analyst.as_bytes(),
            name: &name,
            description: description.as_deref(),
            evidence_provenance_id: evidence.as_ref().map(Uuid::as_bytes),
            members: &signed,
        };
        if check_signature(
            report,
            accounts,
            "behavioural composition",
            &id.to_string(),
            analyst,
            "analyst",
            auth::BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN,
            &auth::behavioural_composition_digest(&composition),
            &signature,
        ) {
            report.checked("behavioural compositions");
        }
    }
    Ok(())
}
