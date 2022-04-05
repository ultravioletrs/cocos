package api

import (
	"fmt"
	"net/http"
)

type pageRes struct {
	Total  uint64 `json:"total"`
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
}

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
			"Location": fmt.Sprintf("/users/%s", res.ID),
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
