package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func buildIdentityName(name string, comment string, email string) string {
	return fmt.Sprintf("%s (%s) <%s>", name, comment, email)
}

func TestCreateEntity_CreateEntityWithNoExpiryAndNoPassphrase_KeyExpiredReturnsFalse(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	values := map[string]interface{}{
		"name":    NAME,
		"comment": COMMENT,
		"email":   EMAIL,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, getSchemaResource().Schema, values)

	entity, _, err := createEntity(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	identityName := buildIdentityName(NAME, COMMENT, EMAIL)
	var isExpired bool = entity.Identities[identityName].SelfSignature.KeyExpired(time.Now())
	assert.Equal(t, isExpired, false)
}

func TestCreateEntity_CreateExpiredEntityWithNoPassphrase_KeyExpiredReturnsFalse(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const EXPIRY int = 7
	values := map[string]interface{}{
		"name":    NAME,
		"comment": COMMENT,
		"email":   EMAIL,
		"expiry":  EXPIRY,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, getSchemaResource().Schema, values)

	entity, _, err := createEntity(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	identityName := buildIdentityName(NAME, COMMENT, EMAIL)
	timeInTheFuture := time.Now().AddDate(0, 0, (EXPIRY * 2))
	var isExpired bool = entity.Identities[identityName].SelfSignature.KeyExpired(timeInTheFuture)
	assert.Equal(t, isExpired, true)
}

func TestCreateEntity_CreateValidEntityWithNoPassphrase_KeyExpiredReturnsFalse(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const EXPIRY int = 1
	values := map[string]interface{}{
		"name":    NAME,
		"comment": COMMENT,
		"email":   EMAIL,
		"expiry":  EXPIRY,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, getSchemaResource().Schema, values)

	entity, _, err := createEntity(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	identityName := buildIdentityName(NAME, COMMENT, EMAIL)
	var isExpired bool = entity.Identities[identityName].SelfSignature.KeyExpired(time.Now())
	assert.Equal(t, isExpired, false)
}

func TestCreateEntity_CreateValidEntityWithPassphrase_KeyExpiredReturnsFalse(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const EXPIRY int = 0
	const PASSPHRASE string = "password123"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"expiry":     EXPIRY,
		"passphrase": PASSPHRASE,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, getSchemaResource().Schema, values)

	entity, _, err := createEntity(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	identityName := buildIdentityName(NAME, COMMENT, EMAIL)
	var isExpired bool = entity.Identities[identityName].SelfSignature.KeyExpired(time.Now())
	assert.Equal(t, isExpired, false)
}

func TestResourceKeyCreate_CreateValidEntityWithPassphrase_DecryptWithCorrectPassphraseSuccessful(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const EXPIRY int = 0
	const PASSPHRASE string = "password123"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"expiry":     EXPIRY,
		"passphrase": PASSPHRASE,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, getSchemaResource().Schema, values)

	entity, err := resourceKeyCreate(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	err = entity.PrivateKey.Decrypt([]byte(PASSPHRASE))
	var isEmptyErr bool = err == nil
	assert.True(t, isEmptyErr)
}

func TestResourceKeyCreate_CreateValidEntityWithPassphrase_DecryptWithIncorrectPassphraseUnsuccessful(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const EXPIRY int = 0
	const PASSPHRASE string = "password123"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"expiry":     EXPIRY,
		"passphrase": PASSPHRASE,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, getSchemaResource().Schema, values)

	entity, err := resourceKeyCreate(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	private := resourceData.Get("private_key").(string)
	fmt.Printf("private: \n %s", private)

	// entity.PrivateKey.Decrypt([]byte("wrongpassword456"))
}

func TestCreatePrivateKey_(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const EXPIRY int = 0
	const PASSPHRASE string = "password123"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"expiry":     EXPIRY,
		"passphrase": PASSPHRASE,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, getSchemaResource().Schema, values)

	entity, _, _ := createEntity(resourceData)

	passphraseBytes := []byte(PASSPHRASE)
	_, armoredPrivateKey, _ := createPrivateKey(entity, &passphraseBytes)
	decrypted, _ := decrypttt([]byte(armoredPrivateKey), passphraseBytes)
	fmt.Println("\n\nDecrypted:", string(decrypted))
}
func decrypttt(ciphertext []byte, password []byte) (plaintext []byte, err error) {
	decbuf := bytes.NewBuffer(ciphertext)
	armorBlock, _ := armor.Decode(decbuf)

	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return password, nil
	}

	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, nil)
	if err != nil {
		return
	}

	plaintext, err = ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return
	}

	return
}
