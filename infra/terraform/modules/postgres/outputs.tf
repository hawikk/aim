output "endpoint" {
  description = "Connection endpoint (host:port)."
  value       = aws_db_instance.this.endpoint
}

output "security_group_id" {
  description = "Security group guarding the database. Attach ingress rules per consumer."
  value       = aws_security_group.db.id
}

output "master_user_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the generated master password."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}
