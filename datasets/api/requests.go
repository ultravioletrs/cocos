package api

import (
	"github.com/ultravioletrs/cocos/datasets"
)

type createReq struct {
	dataset datasets.Dataset
	token   string
}

type listResourcesReq struct {
	owner        string
	pageMetadata datasets.PageMetadata
}

type updateReq struct {
	id          string
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type uploadReq struct {
	owner   string
	token   string
	id      string
	Payload []byte
}

func (req uploadReq) validate() error {
	return nil
}

type viewRequest struct {
	id    string
	owner string
}
