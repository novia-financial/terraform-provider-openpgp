package pgp

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestDataSourceEncryptRead_EncryptsCorrectlyAndNoErrorsThrown(t *testing.T) {
	t.Parallel()

	values := map[string]interface{}{
		"public_key": GetFileContents("test_data/not_passphrase_protected/public_key.asc"),
		"plaintext":  GetFileContents("test_data/not_passphrase_protected/plain_text.txt"),
	}
	var resourceData *schema.ResourceData = schema.TestResourceDataRaw(t, GetPgpEncryptSchema().Schema, values)

	// should give a different result each time
	err := dataSourceEncryptRead(resourceData, nil)
	assert.Equal(t, err, (error)(nil))

	actualCipherTextResult := resourceData.Get("ciphertext").(string)
	assert.NotEmpty(t, actualCipherTextResult)
	assert.Contains(t, actualCipherTextResult, "BEGIN PGP MESSAGE")
}
