package pgp

import (
	"crypto/sha256"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceEncryptRead(d *schema.ResourceData, meta interface{}) error {
	rawPublicKey := d.Get("public_key").(string)
	plainText := d.Get("plaintext").(string)

	ciphertext, err := helper.EncryptMessageArmored(rawPublicKey, plainText)
	if err != nil {
		return err
	}

	hash := sha256.New()
	hash.Write([]byte(ciphertext))

	d.SetId(fmt.Sprintf("%x", hash.Sum(nil)))
	d.Set("ciphertext", string(ciphertext))

	return nil
}
