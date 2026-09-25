package securix.iso27001.access_control

import rego.v1

metadata := {
    "control_id": "ISO-A.8.24",
    "regulation": "ISO27001",
    "title": "Use of Cryptography and Key Management",
    "applies_to": ["hardcoded-secret", "missing-authorization", "weak-crypto"],
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
