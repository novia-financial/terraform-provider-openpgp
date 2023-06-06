package pgp

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceKeyCreateFunc(d *schema.ResourceData, _ interface{}) error {
	_, err := resourceKeyCreate(d)
	return err
}

func resourceKeyCreate(d *schema.ResourceData) (*crypto.Key, error) {
	key, err := createKey(d)
	if err != nil {
		return nil, err
	}

	base64PubKey, armoredPubKey, err := createPublicKey(key)
	if err != nil {
		return nil, err
	}

	passphrase := []byte(d.Get("passphrase").(string))
	key, base64PrivateKey, armoredPrivateKey, err := createPrivateKey(key, passphrase)
	if err != nil {
		return nil, err
	}

	d.SetId(fmt.Sprintf("%x", key.GetEntity().PrimaryKey.Fingerprint))

	d.Set("public_key", armoredPubKey)
	d.Set("public_key_base64", base64PubKey)
	d.Set("private_key", armoredPrivateKey)
	d.Set("private_key_base64", base64PrivateKey)

	return key, nil
}

func createKey(d *schema.ResourceData) (*crypto.Key, error) {
	name := d.Get("name").(string)
	comment := d.Get("comment").(string)
	email := d.Get("email").(string)
	expiryInDays := d.Get("expiry").(int)

	// does this support comments?
	key, err := crypto.GenerateKey(name, email, KeyType_Rsa, KeyType_RsaBits)
	if err != nil {
		return nil, fmt.Errorf("error generating pgp: %v", err)
	}

	// should only be one here
	for _, id := range key.GetEntity().Identities {
		if expiryInDays > 0 {
			var expiryInSeconds uint32 = uint32(expiryInDays * 24 * 60 * 60)
			id.SelfSignature.KeyLifetimeSecs = &expiryInSeconds
		}

		id.UserId.Comment = comment
		err := id.SelfSignature.SignUserId(id.UserId.Id, key.GetEntity().PrimaryKey, key.GetEntity().PrivateKey, nil)
		if err != nil {
			return nil, fmt.Errorf("error signing pgp keys: %v", err)
		}
	}

	return key, nil
}

func createPublicKey(key *crypto.Key) (string, string, error) {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", fmt.Errorf("error armor pgp keys: %v", err)
	}

	key.GetEntity().Serialize(w)
	w.Close()

	return base64.StdEncoding.EncodeToString(buf.Bytes()), buf.String(), nil
}

// returns a base64-private and an armored-private
func createPrivateKey(key *crypto.Key, passphrase []byte) (*crypto.Key, string, string, error) {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("error armor pgp keys: %v", err)
	}

	key.GetEntity().SerializePrivate(w, nil)
	w.Close()

	if len(passphrase) > 0 {
		key, err = key.Lock(passphrase)
		if err != nil {
			return nil, "", "", fmt.Errorf("error locking key: %v", err)
		}

		output, err := key.Armor()
		if err != nil {
			return nil, "", "", fmt.Errorf("error getting armored of locked key: %v", err)
		}

		return key, base64.StdEncoding.EncodeToString([]byte(output)), output, nil
	}

	return key, base64.StdEncoding.EncodeToString(buf.Bytes()), buf.String(), nil
}
