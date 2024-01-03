ui = true
disable_mlock = true

listener "tcp" {
  address          = "localhost:8200"
  cluster_address  = "localhost:8201"
  tls_cert_file    = "vault.crt"
  tls_key_file     = "vault.key"
  tls_disable      = "false"
}

storage "file" {
  path = "vault/data"
}

api_addr = "https://localhost:8200"
cluster_addr = "https://localhost:8201"