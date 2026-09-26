# ─────────────────────────────────────────────────────────────────────────────
# SecuriX Real Target - Multi-Vulnerability Cloud Infrastructure (Checkov)
# ─────────────────────────────────────────────────────────────────────────────

provider "aws" {
  region = "ap-south-1" # Mumbai
}

# 1. S3 Bucket Public Read (CKV_AWS_20 / SEBI-CSCRF-S3.2 / DPDP Sec 8)
resource "aws_s3_bucket" "kyc_documents" {
  bucket = "securix-prod-kyc-documents-mumbai"
  acl    = "public-read" # Vulnerable: public read access
  
  tags = {
    Environment = "production"
    DataClass   = "Confidential-PII"
  }
}

# 2. Overly Permissive Security Group (CKV_AWS_24 / RBI-CSF-NET-2)
resource "aws_security_group" "database_sg" {
  name        = "prod-db-sg"
  description = "Security group for production PostgreSQL"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Vulnerable: SSH open to public internet
  }

  ingress {
    description = "Postgres DB from anywhere"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Vulnerable: DB port open to internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Unencrypted RDS Database Instance (CKV_AWS_16 / RBI Master Direction)
resource "aws_db_instance" "core_banking" {
  identifier          = "core-banking-db"
  allocated_storage   = 100
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.t3.medium"
  username            = "dbadmin"
  password            = "PlaintextPassword2026!" # Vulnerable: hardcoded password
  publicly_accessible = true                      # Vulnerable: publicly exposed
  storage_encrypted   = false                     # Vulnerable: missing KMS encryption
  skip_final_snapshot = true
}

# 4. Wildcard IAM Administrator Policy (CKV_AWS_1 / ISO27001 A.8.2)
resource "aws_iam_policy" "wildcard_access" {
  name        = "securix-wildcard-policy"
  description = "Excessive administrative permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*" # Vulnerable: unrestricted full admin permissions
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
