package pgp

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			GetPgpKeyName(): GetPgpKeySchema(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			GetPgpEncryptName(): GetPgpEncryptSchema(),
			GetPgpDecryptName(): GetPgpDecryptSchema(),
		},
	}
}
