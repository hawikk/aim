# Remote state. The S3 bucket + KMS key are created once, out-of-band
# (see infra/terraform/README.md — bootstrap is intentionally NOT in this
# config to avoid a chicken-and-egg on the state bucket).
terraform {
  backend "s3" {
    bucket       = "aim-terraform-state"
    key          = "dev/terraform.tfstate"
    region       = "eu-west-1"
    encrypt      = true
    use_lockfile = true
  }
}
