terraform {
  required_providers {
    pgp = {
      version = "1.0.5"
      source  = "hashicorp.com/novia-financial/pgp"
    }
  }
}

provider "pgp" {}

resource "pgp_key" "testing" {
  name       = "testing"
  email      = "testing@testing.com"
  comment    = "testing"
  expiry     = 7               # optional
  passphrase = "passphrase123" # optional
}

data "pgp_encrypt" "testing" {
  plaintext  = "thisisasecret"
  public_key = pgp_key.testing.public_key
}

data "pgp_decrypt" "testing" {
  ciphertext  = data.pgp_encrypt.testing.ciphertext
  private_key = pgp_key.testing.private_key
  passphrase  = "passphrase123" # optional
}

output "public_key" {
  value = pgp_key.testing.public_key
}

output "private_key" {
  value = pgp_key.testing.private_key
}

output "private_key_base64" {
  value = pgp_key.testing.private_key_base64
}

output "ciphertext" {
  value = data.pgp_encrypt.testing.ciphertext
}
output "plaintext" {
  value = data.pgp_decrypt.testing.plaintext
}