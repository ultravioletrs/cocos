package sdk

type pageRes struct {
	Total  uint64 `json:"total"`
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
}

type OrganizationsPage struct {
	Organizations []Organization `json:"ogranizations"`
	pageRes
}
