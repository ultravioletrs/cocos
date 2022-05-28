package sdk

import (
	mfx "github.com/mainflux/mainflux/pkg/sdk/go"
)

const (
	consortiumsEndpoint = "consortiums"
)

type Consortium struct{ mfx.Group }

type ConsortiumsPage struct {
	Consortiums []Consortium `json:"consortiums"`
	pageRes
}

func (sdk csdk) CreateConsortium(o Consortium, token string) (string, error) {
	g := mfx.Group{
		Name:        o.Name,
		Description: o.Description,
		ParentID:    o.ParentID,
		Metadata:    o.Metadata,
	}
	return sdk.mf.CreateGroup(g, token)
}

func (sdk csdk) DeleteConsortium(id, token string) error {
	return sdk.mf.DeleteGroup(id, token)
}

func (sdk csdk) AssignToConsortium(memberIDs []string, memberType, consortiumID string, token string) error {
	return sdk.mf.Assign(memberIDs, memberType, consortiumID, token)
}

func (sdk csdk) UnassignFromConsortium(token, consortiumID string, memberIDs ...string) error {
	return sdk.mf.Unassign(token, consortiumID, memberIDs...)
}

func (sdk csdk) ConsortiumMembers(conID, token string, offset, limit uint64) (mfx.MembersPage, error) {
	return sdk.mf.Members(conID, token, offset, limit)
}

func (sdk csdk) Consortiums(offset, limit uint64, token string) (ConsortiumsPage, error) {
	gp, err := sdk.mf.Groups(offset, limit, token)
	if err != nil {
		return ConsortiumsPage{}, err
	}
	ret := ConsortiumsPage{
		Consortiums: make([]Consortium, len(gp.Groups)),
	}
	for _, group := range gp.Groups {
		ret.Consortiums = append(ret.Consortiums, Consortium{group})
	}
	// hack
	ret.pageRes = pageRes{Total: uint64(len(gp.Groups)), Offset: offset, Limit: limit}
	return ret, nil
}

func (sdk csdk) OrganizationByConsortiums(conID string, offset, limit uint64, token string) (ConsortiumsPage, error) {
	groupsPage, err := sdk.mf.Parents(conID, offset, limit, token)
	if err != nil {
		return ConsortiumsPage{}, err
	}
	conPage := ConsortiumsPage{
		Consortiums: make([]Consortium, len(groupsPage.Groups)),
	}
	for _, group := range groupsPage.Groups {
		conPage.Consortiums = append(conPage.Consortiums, Consortium{group})
	}
	conPage.pageRes = pageRes{Total: groupsPage.Total, Offset: offset, Limit: limit}
	return conPage, nil
}

func (sdk csdk) ConsortiumByOrganizations(conID string, offset, limit uint64, token string) (ConsortiumsPage, error) {
	groupsPage, err := sdk.mf.Children(conID, offset, limit, token)
	if err != nil {
		return ConsortiumsPage{}, err
	}
	conPage := ConsortiumsPage{
		Consortiums: make([]Consortium, len(groupsPage.Groups)),
	}
	for _, group := range groupsPage.Groups {
		conPage.Consortiums = append(conPage.Consortiums, Consortium{group})
	}
	conPage.pageRes = pageRes{Total: groupsPage.Total, Offset: offset, Limit: limit}
	return conPage, nil
}

func (sdk csdk) Consortium(conID, token string) (Consortium, error) {
	group, err := sdk.mf.Group(conID, token)
	if err != nil {
		return Consortium{}, err
	}
	return Consortium{
		Group: group,
	}, nil
}

func (sdk csdk) UpdateConsortium(o Consortium, token string) error {
	g := mfx.Group{
		ID:          "",
		Name:        "",
		Description: "",
		ParentID:    "",
		Metadata:    map[string]interface{}{},
	}
	return sdk.mf.UpdateGroup(g, token)
}

func (sdk csdk) ConsortiumMemberships(memberID, token string, offset, limit uint64) (ConsortiumsPage, error) {
	groupsPage, err := sdk.mf.Memberships(memberID, token, offset, limit)
	if err != nil {
		return ConsortiumsPage{}, err
	}
	conPage := ConsortiumsPage{
		Consortiums: make([]Consortium, len(groupsPage.Groups)),
	}
	for _, group := range groupsPage.Groups {
		conPage.Consortiums = append(conPage.Consortiums, Consortium{group})
	}
	// hack
	conPage.pageRes = pageRes{Total: groupsPage.Total, Offset: offset, Limit: limit}
	return conPage, nil
}
