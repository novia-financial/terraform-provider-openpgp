package pgp

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func GetPgpEncryptName() string {
	return "pgp_encrypt"
}

func GetPgpEncryptSchema() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceEncryptRead,
		Schema: map[string]*schema.Schema{
			"plaintext": {
				Type:     schema.TypeString,
				Required: true,
			},
			"public_key": {
				Type:     schema.TypeString,
				Required: true,
			},
			"ciphertext": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}
