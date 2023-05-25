package pgp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createEntity(d *schema.ResourceData) (*openpgp.Entity, *[]byte, error) {
	name := d.Get("name").(string)
	comment := d.Get("comment").(string)
	email := d.Get("email").(string)
	expiryInDays := d.Get("expiry").(int)
	passphrase := d.Get("passphrase").(string)

	e, err := openpgp.NewEntity(name, comment, email, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating pgp: %v", err)
	}

	for _, id := range e.Identities {
		if expiryInDays > 0 {
			var expiryInSeconds uint32 = uint32(expiryInDays * 24 * 60 * 60)
			id.SelfSignature.KeyLifetimeSecs = &expiryInSeconds
		}

		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("error signing pgp keys: %v", err)
		}
	}

	if passphrase == "" {
		return e, nil, nil
	}

	passphraseBytes := []byte(passphrase)
	return e, &passphraseBytes, nil
}

func createPublicKey(e *openpgp.Entity) (string, string, error) {
	b64buf := new(bytes.Buffer)
	b64w := bufio.NewWriter(b64buf)

	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", fmt.Errorf("error armor pgp keys: %v", err)
	}

	e.Serialize(w)
	e.Serialize(b64w)

	w.Close()
	b64w.Flush()

	return base64.StdEncoding.EncodeToString(b64buf.Bytes()), buf.String(), nil
}

func createPrivateKey(e *openpgp.Entity, passphrase *[]byte) (string, string, error) {
	b64buf := new(bytes.Buffer)
	b64w := bufio.NewWriter(b64buf)

	buf := bytes.NewBuffer(nil)
	w, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", "", fmt.Errorf("error armor pgp keys: %v", err)
	}

	var pt io.WriteCloser = nil
	if passphrase != nil {
		pt, _ = openpgp.SymmetricallyEncrypt(w, *passphrase, nil, nil)
	}

	_, err = pt.Write(buf.Bytes())
	e.SerializePrivate(w, nil)
	e.SerializePrivate(b64w, nil)

	if err != nil {
		return "", "", fmt.Errorf("hmm: %v", err)
	}

	if pt != nil {
		pt.Close()
	}
	w.Close()
	b64w.Flush()

	return base64.StdEncoding.EncodeToString(b64buf.Bytes()), buf.String(), nil
}

func resourceKeyCreateFunc(d *schema.ResourceData, _ interface{}) error {
	_, err := resourceKeyCreate(d)
	return err
}

func resourceKeyCreate(d *schema.ResourceData) (*openpgp.Entity, error) {
	e, passphraseBytes, err := createEntity(d)
	if err != nil {
		return nil, err
	}

	base64PubKey, armoredPubKey, err := createPublicKey(e)
	if err != nil {
		return nil, err
	}

	base64PrivateKey, armoredPrivateKey, err := createPrivateKey(e, passphraseBytes)
	if err != nil {
		return nil, err
	}

	d.SetId(fmt.Sprintf("%x", e.PrimaryKey.Fingerprint))

	d.Set("public_key", armoredPubKey)
	d.Set("public_key_base64", base64PubKey)
	d.Set("private_key", armoredPrivateKey)
	d.Set("private_key_base64", base64PrivateKey)

	return e, nil
}
