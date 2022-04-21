package sdk

type assignRequest struct {
	Type    string   `json:"type,omitempty"`
	Members []string `json:"members"`
}

type UserPasswordReq struct {
	OldPassword string `json:"old_password,omitempty"`
	Password    string `json:"password,omitempty"`
}
