package firebase

import (
	"context"
	"encoding/json"
	"firebase.google.com/go"
	fbAuth "firebase.google.com/go/auth"
	"github.com/tinode/chat/server/auth"
	"github.com/tinode/chat/server/store"
	"github.com/tinode/chat/server/store/types"
	"golang.org/x/crypto/bcrypt"
	"time"
)

const scheme string = "fb" // "firebase" text too long for uname format 'firebase:FIREBASE_UID'

type authenticator struct {
	Scheme string
	FbAuth *fbAuth.Client
}

func (a *authenticator) Init(jsonconf json.RawMessage, name string) error {
	return nil
}

func (a *authenticator) AddRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	ctx := context.Background()

	jwtToken := string(secret)

	userRecord, err := a.FbAuth.VerifyIDToken(ctx, jwtToken)
	if err != nil {
		return nil, types.ErrInternal
	}

	fbUid := userRecord.UID

	var expires time.Time
	if rec.Lifetime > 0 {
		expires = time.Now().Add(rec.Lifetime).UTC().Round(time.Millisecond)
	}

	authLevel := rec.AuthLevel
	if authLevel == auth.LevelNone {
		authLevel = auth.LevelAuth
	}

	passhash, err := bcrypt.GenerateFromPassword([]byte(fbUid), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	err = store.Users.AddAuthRecord(rec.Uid, authLevel, a.Scheme, fbUid, passhash, expires)
	if err != nil {
		return nil, err
	}

	rec.AuthLevel = authLevel
	return rec, nil
}

func (a *authenticator) UpdateRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	return nil, types.ErrUnsupported
}

func (a *authenticator) Authenticate(secret []byte) (*auth.Rec, []byte, error) {
	ctx := context.Background()

	jwtToken := string(secret)

	userRecord, err := a.FbAuth.VerifyIDToken(ctx, jwtToken)
	if err != nil {
		return nil, nil, types.ErrInternal
	}

	fbUid := userRecord.UID

	uid, authLvl, _, expires, err := store.Users.GetAuthUniqueRecord(a.Scheme, fbUid)
	if err != nil {
		return nil, nil, err
	}
	if uid.IsZero() {
		// Invalid login.
		return nil, nil, types.ErrFailed
	}
	if !expires.IsZero() && expires.Before(time.Now()) {
		// The record has expired
		return nil, nil, types.ErrExpired
	}

	var lifetime time.Duration
	if !expires.IsZero() {
		lifetime = time.Until(expires)
	}
	return &auth.Rec{
		Uid:       uid,
		AuthLevel: authLvl,
		Lifetime:  lifetime,
		Features:  0,
		State:     types.StateUndefined}, nil, nil
}

func (a *authenticator) AsTag(token string) string {
	return ""
}

func (a *authenticator) IsUnique(secret []byte) (bool, error) {
	ctx := context.Background()

	jwtToken := string(secret)

	userRecord, err := a.FbAuth.VerifyIDToken(ctx, jwtToken)
	if err != nil {
		return false, types.ErrInternal
	}

	fbUid := userRecord.UID

	uid, _, _, _, err := store.Users.GetAuthUniqueRecord(a.Scheme, fbUid)
	if err != nil {
		return false, err
	}

	if uid.IsZero() {
		return true, nil
	}

	return false, types.ErrDuplicate
}

// GenSecret generates a new secret, if appropriate.
func (a *authenticator) GenSecret(rec *auth.Rec) ([]byte, time.Time, error) {
	return nil, time.Time{}, types.ErrUnsupported
}

func (a *authenticator) DelRecords(uid types.Uid) error {
	return nil
}

func (a *authenticator) RestrictedTags() ([]string, error) {
	return nil, nil
}

func (a *authenticator) GetResetParams(uid types.Uid) (map[string]interface{}, error) {
	return nil, nil
}

func init() {
	app, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		panic(err)
	}

	fbAuth, err := app.Auth(context.Background())
	if err != nil {
		panic(err)
	}

	store.RegisterAuthScheme(scheme, &authenticator{
		Scheme: scheme,
		FbAuth: fbAuth,
	})
}
