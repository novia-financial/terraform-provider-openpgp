package pgp

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceDecryptRead(d *schema.ResourceData, meta interface{}) error {
	rawPrivateKey := d.Get("private_key").(string)
	ciphertext := d.Get("ciphertext").(string)
	encoding := d.Get("ciphertext_encoding").(string)

	if encoding == EncodingType_Base64 {
		c, err := base64.StdEncoding.DecodeString(string(ciphertext))
		if err != nil {
			return fmt.Errorf("unable to decode: %v", err)
		}
		ciphertext = string(c)
	}

	// passphrase is optional, so we need a non-passphrase decrypt
	passphrase := d.Get("passphrase").(string)
	plaintext, err := helper.DecryptMessageArmored(rawPrivateKey, []byte(passphrase), ciphertext)
	if err != nil {
		return err
	}

	hash := sha256.New()
	hash.Write([]byte(plaintext))

	d.SetId(fmt.Sprintf("%x", hash.Sum(nil)))
	d.Set("plaintext", string(plaintext))

	return nil
}
