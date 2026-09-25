package securix.rbi.access_control

import rego.v1

metadata := {
    "control_id": "RBI-AC-04",
    "regulation": "RBI",
    "title": "Access to customer data restricted by role",
    "applies_to": ["missing-authorization", "broken-access-control"],
}

default verdict := "PASS"

verdict := "FAIL" if {
    input.finding.category in metadata.applies_to
    input.finding.confirmed
    input.asset.data_sensitivity in {"high", "medium"}
}

result := {
    "control_id": metadata.control_id,
    "verdict": verdict,
    "finding_id": input.finding.finding_id,
}
