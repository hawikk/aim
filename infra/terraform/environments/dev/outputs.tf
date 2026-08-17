output "vpc_id" {
  value = module.network.vpc_id
}

output "db_endpoint" {
  value = module.postgres.endpoint
}

output "db_master_secret_arn" {
  value = module.postgres.master_user_secret_arn
}
