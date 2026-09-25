package securix.dpdp.protection

import rego.v1

metadata := {
    "control_id": "DPDP-SEC-08",
    "regulation": "DPDP",
    "title": "Reasonable security safeguards to prevent personal data breach",
    "applies_to": ["missing-authorization", "data-leak", "hardcoded-secret", "injection"],
}

default verdict := "PASS"

verdict := "FAIL" if {
    input.finding.category in metadata.applies_to
    input.finding.confirmed
    input.asset.data_sensitivity == "high"
}

result := {
    "control_id": metadata.control_id,
    "verdict": verdict,
    "finding_id": input.finding.finding_id,
}
