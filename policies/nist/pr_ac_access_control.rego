package securix.nist.pr_ac

import rego.v1

metadata := {
    "control_id": "NIST-PR-AC-1",
    "regulation": "NIST_CSF",
    "title": "Identities and credentials are managed for authorized devices and users",
    "applies_to": ["missing-authorization", "broken-access-control", "hardcoded-secret"],
}

default verdict := "PASS"

verdict := "FAIL" if {
    input.finding.category in metadata.applies_to
    input.finding.confirmed
}

result := {
    "control_id": metadata.control_id,
    "verdict": verdict,
    "finding_id": input.finding.finding_id,
}
