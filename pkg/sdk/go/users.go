package sdk

import (
	mfx "github.com/mainflux/mainflux/pkg/sdk/go"
)

type User struct{ mfx.User }

func (sdk csdk) CreateUser(token, username, password string) (string, error) {
	u := mfx.User{
		ID:       "",
		Email:    "",
		Groups:   []string{},
		Password: password,
		Metadata: map[string]interface{}{},
	}
	return sdk.mf.CreateUser(token, u)
}

func (sdk csdk) User(token string) (User, error) {
	user, err := sdk.mf.User(token)
	if err != nil {
		return User{}, err
	}
	return User{
		User: user,
	}, nil
}

func (sdk csdk) CreateToken(user User) (string, error) {
	return sdk.mf.CreateToken(user.User)
}

func (sdk csdk) UpdateUser(u User, token string) error {
	uu := mfx.User{
		ID:       u.ID,
		Email:    u.Email,
		Groups:   u.Groups,
		Password: u.Password,
		Metadata: u.Metadata,
	}
	return sdk.mf.UpdateUser(uu, token)
}

func (sdk csdk) UpdatePassword(oldPass, newPass, token string) error {
	return sdk.mf.UpdatePassword(oldPass, newPass, token)
}
