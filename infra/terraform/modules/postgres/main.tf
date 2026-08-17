# Managed PostgreSQL with secure defaults:
# - private only (no public access)
# - storage + KMS encryption at rest
# - master password generated and managed in Secrets Manager by RDS
# - automated backups with 7-day retention
# - deletion protection on

resource "aws_security_group" "db" {
  name        = "${var.name}-db"
  description = "PostgreSQL access from inside the VPC only"
  vpc_id      = var.vpc_id

  # No ingress rules here by default — attach aws_security_group_rule
  # resources per consumer service so access is explicit and reviewable.

  egress = []

  tags = merge(var.tags, { Name = "${var.name}-db" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "this" {
  identifier = var.name

  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name  = var.database_name
  username = var.master_username

  # RDS generates the master password and stores it in Secrets Manager.
  manage_master_user_password = true

  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.allocated_storage_gb * 4
  storage_type          = "gp3"
  storage_encrypted     = true

  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false

  backup_retention_period   = 7
  backup_window             = "03:00-04:00"
  maintenance_window        = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot     = true
  delete_automated_backups  = false
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"

  performance_insights_enabled = true

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = var.tags
}
