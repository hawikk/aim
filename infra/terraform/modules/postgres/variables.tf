variable "name" {
  description = "Name prefix for the database resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC the database lives in."
  type        = string
}

variable "db_subnet_group_name" {
  description = "DB subnet group (private subnets only)."
  type        = string
}

variable "engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "16.6"
}

variable "instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "allocated_storage_gb" {
  description = "Initial storage in GiB (autoscaling enabled up to max_allocated_storage)."
  type        = number
  default     = 50
}

variable "database_name" {
  description = "Initial database name."
  type        = string
  default     = "aim"
}

variable "master_username" {
  description = "Master username. The password is generated and stored in Secrets Manager by RDS."
  type        = string
  default     = "aim_admin"
}

variable "deletion_protection" {
  description = "Block accidental deletion. Keep true outside throwaway envs."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to all database resources."
  type        = map(string)
  default     = {}
}
