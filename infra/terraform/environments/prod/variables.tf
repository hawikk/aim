variable "region" {
  description = "AWS region for the prod environment."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Name prefix for all prod resources."
  type        = string
  default     = "aim-prod"
}
