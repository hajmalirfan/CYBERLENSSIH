resource "aws_s3_bucket" "data" {
  bucket = "my-prototype-bucket"
  # Intentionally missing server_side_encryption_configuration for Checkov demo
  acl = "public-read"
}
