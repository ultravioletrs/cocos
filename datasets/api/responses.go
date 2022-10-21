package api

import (
	"fmt"
	"net/http"

	"github.com/ultravioletrs/cocos/datasets"
)

type createRes struct {
	ID      string
	created bool
}

func (res createRes) Code() int {
	if res.created {
		return http.StatusCreated
	}

	return http.StatusOK
}

func (res createRes) Headers() map[string]string {
	if res.created {
		return map[string]string{
			"Location": fmt.Sprintf("/datasets/%s", res.ID),
		}
	}
	return map[string]string{}
}

func (res createRes) Empty() bool {
	return true
}

type errorRes struct {
	Err string `json:"error"`
}

type removeRes struct{}

func (res removeRes) Code() int {
	return http.StatusNoContent
}

func (res removeRes) Headers() map[string]string {
	return map[string]string{}
}

func (res removeRes) Empty() bool {
	return true
}

type viewRes struct {
	datasets.Dataset
}

func (res viewRes) Code() int {
	return http.StatusOK
}

func (res viewRes) Headers() map[string]string {
	return map[string]string{}
}

func (res viewRes) Empty() bool {
	return false
}

type datasetsPageRes struct {
	pageRes
	Datasets []datasets.Dataset `json:"datasets"`
}

func (res datasetsPageRes) Code() int {
	return http.StatusOK
}

func (res datasetsPageRes) Headers() map[string]string {
	return map[string]string{}
}

func (res datasetsPageRes) Empty() bool {
	return false
}

type pageRes struct {
	Total  uint64 `json:"total"`
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
	Order  string `json:"order"`
	Dir    string `json:"direction"`
}
