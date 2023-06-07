package pgp

import (
	"math/rand"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
)

func TestCreateKey_CreateEntityWithNoExpiry_KeyExpiredReturnsFalse(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	values := map[string]interface{}{
		"name":    NAME,
		"comment": COMMENT,
		"email":   EMAIL,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, err := createKey(resourceData)
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	var isExpired bool = IsKeyExpired(key, time.Now())
	assert.Equal(t, isExpired, false)
}

func TestCreateKey_CreateExpiredEntity_KeyExpiredReturnsTrue(t *testing.T) {
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
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, err := createKey(resourceData)
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	timeInTheFuture := time.Now().AddDate(0, 0, (EXPIRY * 2))
	var isExpired bool = IsKeyExpired(key, timeInTheFuture)
	assert.Equal(t, isExpired, true)
}

func TestCreateKey_CreateValidEntity_KeyExpiredReturnsFalse(t *testing.T) {
	t.Parallel()

	rand.Seed(time.Now().UnixNano()) // need to seed the PRNG before using rand

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	var expiry int = rand.Intn(ExpiryInDaysMaximum-ExpiryInDaysMinimum) + ExpiryInDaysMinimum // get a random uint between 1000 and 1
	values := map[string]interface{}{
		"name":    NAME,
		"comment": COMMENT,
		"email":   EMAIL,
		"expiry":  expiry,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, err := createKey(resourceData)
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	var isExpired bool = IsKeyExpired(key, time.Now())
	assert.Equal(t, isExpired, false)
}

func TestCreatePrivateKey_WithPassphraseAndExpiry_PrivateKeyIsEncrypted(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const EXPIRY int = 1
	const passphrase string = "novia"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"expiry":     EXPIRY,
		"passphrase": passphrase,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, _ := createKey(resourceData)
	p := []byte(passphrase)
	key, _, _, err := createPrivateKey(key, p)
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))
	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, true)
}

func TestCreatePrivateKey_WithPassphraseAndNoExpiry_PrivateKeyIsEncrypted(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const passphrase string = "novia"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"passphrase": passphrase,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, _ := createKey(resourceData)
	p := []byte(passphrase)
	key, _, _, err := createPrivateKey(key, p)
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))
	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, true)
}

func TestCreatePrivateKey_WithNoPassphraseAndNoExpiry_PrivateKeyIsNotEncrypted(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	values := map[string]interface{}{
		"name":    NAME,
		"comment": COMMENT,
		"email":   EMAIL,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, _ := createKey(resourceData)
	key, _, _, err := createPrivateKey(key, []byte{})
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))
	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, false)
}

func TestCreatePrivateKey_WithNoPassphraseAndExpiry_PrivateKeyIsNotEncrypted(t *testing.T) {
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
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, _ := createKey(resourceData)
	key, _, _, err := createPrivateKey(key, []byte{})
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))
	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, false)
}

func TestCreatePrivateKey_WithPassphrase_CanBeDecryptedWithCorrectPassphrase(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const PASSPHRASE string = "passphrase"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"passphrase": PASSPHRASE,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, _ := createKey(resourceData)
	key, _, _, err := createPrivateKey(key, []byte(PASSPHRASE))
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, true)
	err = key.GetEntity().PrivateKey.Decrypt([]byte(PASSPHRASE))
	assert.Equal(t, err, (error)(nil))
	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, false)
}

func TestCreatePrivateKey_WithPassphrase_DecryptingWithIncorrectPassphraseFails(t *testing.T) {
	t.Parallel()

	const NAME string = "nameeee"
	const COMMENT string = "commentttt"
	const EMAIL string = "emaillll"
	const PASSPHRASE string = "passphrase"
	values := map[string]interface{}{
		"name":       NAME,
		"comment":    COMMENT,
		"email":      EMAIL,
		"passphrase": PASSPHRASE,
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpKeySchema().Schema, values)

	key, _ := createKey(resourceData)
	key, _, _, err := createPrivateKey(key, []byte(PASSPHRASE))
	assert.NotEqual(t, key.GetEntity(), (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, true)
	err = key.GetEntity().PrivateKey.Decrypt([]byte("wrongpassphrase"))
	assert.NotEqual(t, err, (error)(nil))
	assert.Equal(t, key.GetEntity().PrivateKey.Encrypted, true)
}

func IsKeyExpired(key *crypto.Key, t time.Time) bool {
	i := key.GetEntity().PrimaryIdentity()
	return key.GetEntity().PrimaryKey.KeyExpired(i.SelfSignature, t) || // primary key has expired
		i.SelfSignature.SigExpired(t) // user ID self-signature has expired
}
