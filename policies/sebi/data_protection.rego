package securix.sebi.data_protection

import rego.v1

metadata := {
    "control_id": "SEBI-CSCRF-S3.2",
    "regulation": "SEBI",
    "title": "Cloud Data Protection & Access Control Segregation",
    "applies_to": ["cloud-storage-misconfiguration", "public-exposure", "data-leak"],
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
