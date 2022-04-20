package sdk

type assignRequest struct {
	Type    string   `json:"type,omitempty"`
	Members []string `json:"members"`
}
