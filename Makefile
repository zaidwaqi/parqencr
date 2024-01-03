.PHONY: install-vault

pre:
	@echo "Generate TLS Certificates and Ensure Certificates are Trusted"
	@openssl req -x509 -newkey rsa:4096 -sha256 -utf8 -days 365 -nodes -config ./openssl.conf -keyout ./vault.key -out ./vault.crt
	@cp vault.crt /etc/ssl/certs/vault.crt
	
install-vault:
	@echo "Installing Vault"
	@dnf -y install dnf-plugins-core
	@dnf config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
	@dnf -y install vault
	@setcap cap_ipc_lock= /usr/bin/vault

initialize-vault-dev:
	@vault server -dev -dev-root-token-id=B38woSMKwOIJjcwg4mHGmtBDTUJ7ikWe0kCGVnxoJNWnwTyEyE1vckS2CuYbdK9S

initialize-vault:
	@vault server -config=vault.hcl
	@vault operator init
	@vault operator unseal

enable-transit-engine:
	@vault secrets enable -path=transit transit
