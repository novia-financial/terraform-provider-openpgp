package pgp

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
)

func buildIdentityName(name string, comment string, email string) string {
	return fmt.Sprintf("%s (%s) <%s>", name, comment, email)
}

func TestCreateEntity_CreateEntityWithNoExpiry_KeyExpiredReturnsFalse(t *testing.T) {
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

	entity, err := createEntity(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	identityName := buildIdentityName(NAME, COMMENT, EMAIL)
	var isExpired bool = entity.Identities[identityName].SelfSignature.KeyExpired(time.Now())
	assert.Equal(t, isExpired, false)
}

func TestCreateEntity_CreateExpiredEntity_KeyExpiredReturnsTrue(t *testing.T) {
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

	entity, err := createEntity(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	identityName := buildIdentityName(NAME, COMMENT, EMAIL)
	timeInTheFuture := time.Now().AddDate(0, 0, (EXPIRY * 2))
	var isExpired bool = entity.Identities[identityName].SelfSignature.KeyExpired(timeInTheFuture)
	assert.Equal(t, isExpired, true)
}

func TestCreateEntity_CreateValidEntity_KeyExpiredReturnsFalse(t *testing.T) {
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

	entity, err := createEntity(resourceData)
	assert.NotEqual(t, entity, (*openpgp.Entity)(nil))
	assert.Equal(t, err, (error)(nil))

	identityName := buildIdentityName(NAME, COMMENT, EMAIL)
	var isExpired bool = entity.Identities[identityName].SelfSignature.KeyExpired(time.Now())
	assert.Equal(t, isExpired, false)
}
