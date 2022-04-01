package sdk

import (
	mfsdk "github.com/mainflux/mainflux/pkg/sdk/go"
)

func (sdk cSDK) CreateUser(token, username, password string) (string, error) {
	u := mfsdk.User{
		Email:    username,
		Password: password,
	}
}
