package api

import (
	"fmt"
	"net/http"

	"github.com/ultravioletrs/cocos/computations"
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
			"Location": fmt.Sprintf("/computations/%s", res.ID),
		}
	}

	return map[string]string{}
}

func (res createRes) Empty() bool {
	return true
}

type viewRes struct {
	computations.Computation
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

type errorRes struct {
	Err string `json:"error"`
}

type listRes struct {
	computations.Page
}

func (res listRes) Code() int {
	return http.StatusOK
}

func (res listRes) Headers() map[string]string {
	return map[string]string{}
}

func (res listRes) Empty() bool {
	return false
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
