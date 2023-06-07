package pgp

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func GetPgpDecryptName() string {
	return "pgp_decrypt"
}

func GetPgpDecryptSchema() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceDecryptRead,
		Schema: map[string]*schema.Schema{
			"plaintext": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"private_key": {
				Type:     schema.TypeString,
				Required: true,
			},
			"ciphertext": {
				Type:     schema.TypeString,
				Required: true,
			},
			"passphrase": {
				Type:         schema.TypeString,
				ForceNew:     true,
				Optional:     true,
				Default:      "",
				ValidateFunc: validation.StringLenBetween(PassphraseLengthMinimum, PassphraseLengthMaximum),
			},
			"ciphertext_encoding": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  EncodingType_Armored,
				ValidateFunc: func(val interface{}, key string) (_ []string, errs []error) {
					v := val.(string)

					if v != EncodingType_Armored && v != EncodingType_Base64 {
						errs = append(errs, fmt.Errorf("%q must be either 'armored' or 'base64', got: %s", key, v))
					}

					return
				},
			},
		},
	}
}
