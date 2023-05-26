package pgp

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func getSchemaResource() *schema.Resource {
	return &schema.Resource{
		Create: resourceKeyCreateFunc,
		Read:   schema.Noop,
		Delete: schema.RemoveFromState,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(NameLengthMinimum, NameLengthMaximum),
			},
			"comment": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},
			"email": {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
			},
			"expiry": {
				Type:         schema.TypeInt,
				ForceNew:     true,
				Required:     false,
				Default:      0,
				ValidateFunc: validation.IntBetween(ExpiryInDaysMinimum, ExpiryInDaysMaximum),
			},

			"public_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Armored PGP Public Key",
			},
			"public_key_base64": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Base64 Encoded Public Key",
			},
			"private_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Armored PGP Private Key",
			},
			"private_key_base64": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Base64 Encoded Private Key",
			},
		},
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
	}
}
