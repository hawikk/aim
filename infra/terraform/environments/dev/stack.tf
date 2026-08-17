module "network" {
  source = "../../modules/network"

  name = var.name
}

module "postgres" {
  source = "../../modules/postgres"

  name                 = "${var.name}-pg"
  vpc_id               = module.network.vpc_id
  db_subnet_group_name = module.network.db_subnet_group_name
}
