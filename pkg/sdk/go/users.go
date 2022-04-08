package sdk

import mfx "github.com/mainflux/mainflux/pkg/sdk/go"

func (sdk cSDK) CreateUser(token, username, password string) (string, error) {
	u := mfx.User{
		ID:       "",
		Email:    "",
		Groups:   []string{},
		Password: password,
		Metadata: map[string]interface{}{},
	}
	return sdk.mf.CreateUser(token, u)
}
