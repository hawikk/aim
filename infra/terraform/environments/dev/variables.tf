variable "region" {
  description = "AWS region for the dev environment."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Name prefix for all dev resources."
  type        = string
  default     = "aim-dev"
}
