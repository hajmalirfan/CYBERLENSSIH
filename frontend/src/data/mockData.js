export const INITIAL_RISK_QUEUE = [
  {
    finding_id: 'zap_sqli_transfer_endpoint_004',
    asset_id: 'url://api.fintech.internal/v1/transfer',
    asset_name: 'Fund Transfer API Endpoint',
    tool: 'zap',
    rule_id: '40018',
    title: 'SQL Injection Vulnerability in Account Balance Lookup',
    severity: 'critical',
    expected_annual_loss_inr: 5800000,
    formatted_exposure_inr: '₹58.0 Lakhs',
    category: 'web',
    verified: false,
    fair_breakdown: {
      loss_event_frequency: 0.8,
      loss_magnitude_inr: 7250000,
      primary_loss_inr: 3000000,
      secondary_loss_inr: 2800000,
      formatted_inr: '₹58.0 Lakhs'
    },
    remediation: 'Use parameterized queries or ORM binding. Never concatenate user input into SQL queries.',
    evidence: "Parameter account_id vulnerable with payload: 1001 OR 1=1 -- response time: 2400ms"
  },
  {
    finding_id: 'semgrep_hardcoded_jwt_secret_001',
    asset_id: 'repo://fintech/payment-gateway',
    asset_name: 'Payment Gateway Core',
    tool: 'semgrep',
    rule_id: 'generic.secrets.jwt-hardcoded-secret',
    title: 'Hardcoded JWT Signing Secret in Payment Handler',
    severity: 'critical',
    expected_annual_loss_inr: 4550000,
    formatted_exposure_inr: '₹45.5 Lakhs',
    category: 'code',
    verified: false,
    fair_breakdown: {
      loss_event_frequency: 0.7,
      loss_magnitude_inr: 6500000,
      primary_loss_inr: 2500000,
      secondary_loss_inr: 2050000,
      formatted_inr: '₹45.5 Lakhs'
    },
    remediation: 'Move secrets to HashiCorp Vault or AWS Secrets Manager. Do not store credentials in source control.',
    evidence: 'JWT_SECRET = "super_secret_production_key_2026_securix_key"'
  },
  {
    finding_id: 'falco_interactive_shell_005',
    asset_id: 'image://registry.internal/checkout-api:v2.4',
    asset_name: 'Checkout API Container',
    tool: 'falco',
    rule_id: 'Terminal shell in container',
    title: 'Interactive Bash Shell Spawned Inside Production Container',
    severity: 'critical',
    expected_annual_loss_inr: 3400000,
    formatted_exposure_inr: '₹34.0 Lakhs',
    category: 'runtime',
    verified: false,
    fair_breakdown: {
      loss_event_frequency: 0.6,
      loss_magnitude_inr: 5666666,
      primary_loss_inr: 1400000,
      secondary_loss_inr: 2000000,
      formatted_inr: '₹34.0 Lakhs'
    },
    remediation: 'Enforce read-only root filesystems and drop CAP_SYS_ADMIN capabilities from container pods.',
    evidence: 'falco alert: Notice A shell was spawned in a container with an attached terminal (user=root container_id=e7b42a9fd)'
  },
  {
    finding_id: 'suricata_c2_traffic_006',
    asset_id: 'url://api.fintech.internal/v1/transfer',
    asset_name: 'Fund Transfer API Endpoint',
    tool: 'suricata',
    rule_id: '2018959',
    title: 'Outbound Cobalt Strike C2 Beaconing Detected',
    severity: 'high',
    expected_annual_loss_inr: 2750000,
    formatted_exposure_inr: '₹27.5 Lakhs',
    category: 'network',
    verified: true,
    fair_breakdown: {
      loss_event_frequency: 0.5,
      loss_magnitude_inr: 5500000,
      primary_loss_inr: 1250000,
      secondary_loss_inr: 1500000,
      formatted_inr: '₹27.5 Lakhs'
    },
    remediation: 'Isolate the compromised host immediately, analyze host memory, and rotate all network credentials.',
    evidence: 'ET MALWARE Cobalt Strike Beaconing User-Agent observed on port 443 destination: 198.51.100.23'
  },
  {
    finding_id: 'checkov_s3_bucket_public_002',
    asset_id: 'iac://cloud/aws-production-vpc',
    asset_name: 'AWS Production VPC Terraform',
    tool: 'checkov',
    rule_id: 'CKV_AWS_20',
    title: 'S3 Bucket has Public Read Access Enabled in Production',
    severity: 'high',
    expected_annual_loss_inr: 1820000,
    formatted_exposure_inr: '₹18.2 Lakhs',
    category: 'infrastructure',
    verified: true,
    fair_breakdown: {
      loss_event_frequency: 0.4,
      loss_magnitude_inr: 4550000,
      primary_loss_inr: 820000,
      secondary_loss_inr: 1000000,
      formatted_inr: '₹18.2 Lakhs'
    },
    remediation: 'Set acl = "private" and enable aws_s3_bucket_public_access_block resource in Terraform.',
    evidence: 'resource "aws_s3_bucket" "data" { acl = "public-read" }'
  },
  {
    finding_id: 'cosign_unsigned_container_003',
    asset_id: 'image://registry.internal/checkout-api:v2.4',
    asset_name: 'Checkout API Container',
    tool: 'cosign',
    rule_id: 'COSIGN_SIGNATURE_MISSING',
    title: 'Production Container Image Lacks Valid Cryptographic Signature',
    severity: 'high',
    expected_annual_loss_inr: 1250000,
    formatted_exposure_inr: '₹12.5 Lakhs',
    category: 'supply-chain',
    verified: false,
    fair_breakdown: {
      loss_event_frequency: 0.25,
      loss_magnitude_inr: 5000000,
      primary_loss_inr: 500000,
      secondary_loss_inr: 750000,
      formatted_inr: '₹12.5 Lakhs'
    },
    remediation: 'Configure CI pipeline with cosign sign --key in GitHub Actions before deploying to Kubernetes.',
    evidence: 'cosign verify: Error: no matching signatures found for image registry.internal/checkout-api:v2.4'
  }
];

export const COMPLIANCE_REGULATIONS = [
  { reg: 'RBI', name: 'RBI IT & Cyber Security Framework', score: 85, pass: 14, fail: 3, authority: 'Reserve Bank of India' },
  { reg: 'SEBI', name: 'SEBI CSCRF Framework', score: 88, pass: 12, fail: 2, authority: 'Securities and Exchange Board of India' },
  { reg: 'DPDP', name: 'Digital Personal Data Protection Act', score: 79, pass: 9, fail: 3, authority: 'Ministry of Electronics and IT' },
  { reg: 'CERT-In', name: 'CERT-In 6-Hour Incident Reporting', score: 92, pass: 11, fail: 1, authority: 'Indian Computer Emergency Response Team' },
  { reg: 'ISO27001', name: 'ISO/IEC 27001:2022 ISMS', score: 91, pass: 22, fail: 2, authority: 'International Organization for Standardization' },
  { reg: 'NIST_CSF', name: 'NIST CSF 2.0 Security Core', score: 82, pass: 18, fail: 4, authority: 'National Institute of Standards and Tech' }
];

export const OPA_VERDICTS = [
  { reg: 'RBI', control: 'RBI-CSF-SEC-4.1', title: 'Cryptographic Key Management', status: 'FAIL', severity: 'HIGH', reason: 'Hardcoded JWT secret in source repository violates RBI Master Direction section 4.1' },
  { reg: 'SEBI', control: 'SEBI-CSCRF-S3.2', title: 'Cloud Data Protection & Storage Isolation', status: 'FAIL', severity: 'HIGH', reason: 'Public S3 bucket without bucket policy fails SEBI cloud storage isolation guidelines' },
  { reg: 'ISO27001', control: 'A.8.30', title: 'Outsourced Development & Supply Chain', status: 'FAIL', severity: 'MEDIUM', reason: 'Container image lacks Sigstore Cosign signature verification in CI/CD pipeline' },
  { reg: 'DPDP', control: 'DPDP-ACT-SEC-8', title: 'Personal Data Technical Safeguards', status: 'FAIL', severity: 'CRITICAL', reason: 'SQL injection exposes personal financial transaction records to unauthorized extraction' },
  { reg: 'NIST_CSF', control: 'DE.CM-1', title: 'Continuous Runtime Monitoring', status: 'FAIL', severity: 'CRITICAL', reason: 'Falco kernel probe observed unauthorized bash execution in production container' },
  { reg: 'CERT-In', control: 'CERT-IN-DIR-5', title: 'Malicious Traffic Logging & 6-Hour Notice', status: 'FAIL', severity: 'HIGH', reason: 'C2 beaconing detected; requires mandatory notification within 6 hours of discovery' }
];

export const TOPOLOGY_SERVICES = [
  { name: 'Semgrep Service', port: '8001', type: 'SAST Code Security', status: 'HEALTHY', latency: '42ms', member: 'Member 1' },
  { name: 'Checkov Service', port: '8002', type: 'IaC & Terraform Audit', status: 'HEALTHY', latency: '68ms', member: 'Member 1' },
  { name: 'Cosign Service', port: '8003', type: 'Container Sigstore Verifier', status: 'HEALTHY', latency: '19ms', member: 'Member 2' },
  { name: 'Falco Service', port: '8004', type: 'Runtime Kernel eBPF Probe', status: 'HEALTHY', latency: '12ms', member: 'Member 3' },
  { name: 'Suricata Service', port: '8005', type: 'Network IDS / PCAP Engine', status: 'HEALTHY', latency: '35ms', member: 'Member 3' },
  { name: 'ZAP Service', port: '8006', type: 'DAST Web Vulnerability Scanner', status: 'HEALTHY', latency: '120ms', member: 'Member 4' },
  { name: 'graph-service', port: '8010', type: 'Apache AGE + PostgreSQL', status: 'HEALTHY', latency: '8ms', member: 'Shared Hub' },
  { name: 'temporal-orchestrator', port: '8011', type: 'Workflow State Machine', status: 'HEALTHY', latency: '15ms', member: 'Shared Hub' },
  { name: 'evidence-generator', port: '8012', type: 'Cryptographic SHA-256 OTS', status: 'HEALTHY', latency: '24ms', member: 'Member 6' },
  { name: 'agent-mesh', port: '8013', type: 'PyFair ₹ & OPA Rego Engine', status: 'HEALTHY', latency: '54ms', member: 'Member 5' }
];

export const ATTACK_GRAPH_NODES = [
  { id: 'asset_1', label: 'Payment Gateway', type: 'asset', color: '#3b82f6', x: 100, y: 180 },
  { id: 'asset_2', label: 'Transfer API URL', type: 'asset', color: '#3b82f6', x: 100, y: 320 },
  { id: 'asset_3', label: 'Checkout Container', type: 'asset', color: '#3b82f6', x: 100, y: 460 },
  { id: 'vuln_1', label: 'Hardcoded Secret', type: 'vuln', color: '#ef4444', x: 340, y: 140 },
  { id: 'vuln_2', label: 'SQL Injection', type: 'vuln', color: '#ef4444', x: 340, y: 280 },
  { id: 'vuln_3', label: 'Unsigned Image', type: 'vuln', color: '#f59e0b', x: 340, y: 420 },
  { id: 'vuln_4', label: 'Interactive Shell', type: 'vuln', color: '#ef4444', x: 340, y: 520 },
  { id: 'threat_1', label: 'Credential Abuse', type: 'threat', color: '#a855f7', x: 580, y: 200 },
  { id: 'threat_2', label: 'Data Exfiltration', type: 'threat', color: '#a855f7', x: 580, y: 340 },
  { id: 'impact_1', label: 'RBI Violation (₹45.5L)', type: 'impact', color: '#ec4899', x: 800, y: 200 },
  { id: 'impact_2', label: 'DPDP Fine (₹58.0L)', type: 'impact', color: '#ec4899', x: 800, y: 340 }
];

export const ATTACK_GRAPH_EDGES = [
  { from: 'asset_1', to: 'vuln_1', label: 'CONTAINS' },
  { from: 'asset_2', to: 'vuln_2', label: 'EXPOSES' },
  { from: 'asset_3', to: 'vuln_3', label: 'BUILT_FROM' },
  { from: 'asset_3', to: 'vuln_4', label: 'SPAWNED' },
  { from: 'vuln_1', to: 'threat_1', label: 'ENABLES' },
  { from: 'vuln_2', to: 'threat_2', label: 'PERMITS' },
  { from: 'vuln_4', to: 'threat_2', label: 'LATERAL_MOVE' },
  { from: 'threat_1', to: 'impact_1', label: 'CAUSES' },
  { from: 'threat_2', to: 'impact_2', label: 'PENALIZES' }
];
