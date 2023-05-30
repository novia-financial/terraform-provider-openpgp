package pgp

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider -
func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"pgp_key": getSchemaResource(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"pgp_encrypt": dataSourceEncrypt(),
			"pgp_decrypt": dataSourceDecrypt(),
		},
	}
}
