package firebase

import (
	"encoding/json"
	"github.com/tinode/chat/server/auth"
	"github.com/tinode/chat/server/store/types"
	"time"
)

type authenticator struct {
}

func (a *authenticator) Init(jsonconf json.RawMessage, name string) error {
	return nil
}

func (a *authenticator) AddRecord(jsonconf json.RawMessage, name string) error {
	return nil
}

func (a *authenticator) UpdateRecord(jsonconf json.RawMessage, name string) error {
	return nil
}

func (a *authenticator) Authenticate(secret []byte) (*Rec, []byte, error) {
}

func (a *authenticator) AsTag(token string) string {
	return ""
}

func (a *authenticator) IsUnique(secret []byte) (bool, error) {

}

// GenSecret generates a new secret, if appropriate.
func (a *authenticator) GenSecret(rec *auth.Rec) ([]byte, time.Time, error) {
}

func (a *authenticator) DelRecords(uid types.Uid) error {
	return nil
}

func (a *authenticator) RestrictedTags() ([]string, error) {
}

func (a *authenticator) GetResetParams(uid types.Uid) (map[string]interface{}, error) {
	return nil, nil
}
