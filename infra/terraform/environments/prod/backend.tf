# Remote state. Same bootstrap rules as dev — see infra/terraform/README.md.
terraform {
  backend "s3" {
    bucket       = "aim-terraform-state"
    key          = "prod/terraform.tfstate"
    region       = "eu-west-1"
    encrypt      = true
    use_lockfile = true
  }
}
