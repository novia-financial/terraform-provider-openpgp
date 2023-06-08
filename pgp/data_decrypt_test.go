package pgp

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestDataSourceDecryptRead_PassphraseProtected_DecryptsCorrectly(t *testing.T) {
	t.Parallel()

	values := map[string]interface{}{
		"private_key": GetFileContents("test_data/passphrase_protected/private_key.asc"),
		"ciphertext":  GetFileContents("test_data/passphrase_protected/cipher_text.asc"),
		"passphrase":  GetFileContents("test_data/passphrase_protected/passphrase.txt"),
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpDecryptSchema().Schema, values)

	err := dataSourceDecryptRead(resourceData, nil)
	assert.Equal(t, err, (error)(nil))

	expectedPlainTextResult := GetFileContents("test_data/passphrase_protected/plain_text.txt")
	actualPlainTextResult := resourceData.Get("plaintext").(string)
	assert.Equal(t, expectedPlainTextResult, actualPlainTextResult)
}

func TestDataSourceDecryptRead_NotPassphraseProtected_DecryptsCorrectly(t *testing.T) {
	t.Parallel()

	values := map[string]interface{}{
		"private_key": GetFileContents("test_data/not_passphrase_protected/private_key.asc"),
		"ciphertext":  GetFileContents("test_data/not_passphrase_protected/cipher_text.asc"),
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpDecryptSchema().Schema, values)

	err := dataSourceDecryptRead(resourceData, nil)
	assert.Equal(t, err, (error)(nil))

	expectedPlainTextResult := GetFileContents("test_data/not_passphrase_protected/plain_text.txt")
	actualPlainTextResult := resourceData.Get("plaintext").(string)
	assert.Equal(t, expectedPlainTextResult, actualPlainTextResult)
}
