package sdk

import (
	mfx "github.com/mainflux/mainflux/pkg/sdk/go"
)

const (
	organizationsEndpoint = "organizations"
	MaxLevel              = uint64(5)
	MinLevel              = uint64(1)
)

type Organization struct{ mfx.Group }

type OrganizationsPage struct {
	Organizations []Organization `json:"organizations"`
	pageRes
}

func (sdk csdk) CreateOrganization(o Organization, token string) (string, error) {
	g := mfx.Group{
		Name:        o.Name,
		Description: o.Description,
		ParentID:    o.ParentID,
		Metadata:    o.Metadata,
	}
	return sdk.mf.CreateGroup(g, token)
}

func (sdk csdk) DeleteOrganization(id, token string) error {
	return sdk.mf.DeleteGroup(id, token)
}

func (sdk csdk) AssignToOrganization(memberIDs []string, memberType, organizationID string, token string) error {
	return sdk.mf.Assign(memberIDs, memberType, organizationID, token)
}

func (sdk csdk) UnassignFromOrganization(token, organizationID string, memberIDs ...string) error {
	return sdk.mf.Unassign(token, organizationID, memberIDs...)
}

func (sdk csdk) OrganizationMembers(orgId, token string, offset, limit uint64) (mfx.MembersPage, error) {
	return sdk.mf.Members(orgId, token, offset, limit)
}

func (sdk csdk) Organizations(offset, limit uint64, token string) (OrganizationsPage, error) {
	gp, err := sdk.mf.Groups(offset, limit, token)
	if err != nil {
		return OrganizationsPage{}, err
	}
	ret := OrganizationsPage{
		Organizations: make([]Organization, len(gp.Groups)),
	}
	for _, group := range gp.Groups {
		ret.Organizations = append(ret.Organizations, Organization{group})
	}
	// hack
	ret.pageRes = pageRes{Total: uint64(len(gp.Groups)), Offset: offset, Limit: limit}
	return ret, nil
}

func (sdk csdk) Organization(orgId, token string) (Organization, error) {
	group, err := sdk.mf.Group(orgId, token)
	if err != nil {
		return Organization{}, err
	}
	return Organization{
		Group: group,
	}, nil
}

func (sdk csdk) UpdateOrganization(o Organization, token string) error {
	g := mfx.Group{
		ID:          "",
		Name:        "",
		Description: "",
		ParentID:    "",
		Metadata:    map[string]interface{}{},
	}
	return sdk.mf.UpdateGroup(g, token)
}

func (sdk csdk) OrganizationMemberships(memberID, token string, offset, limit uint64) (OrganizationsPage, error) {
	groupsPage, err := sdk.mf.Memberships(memberID, token, offset, limit)
	if err != nil {
		return OrganizationsPage{}, err
	}
	orgPage := OrganizationsPage{
		Organizations: make([]Organization, len(groupsPage.Groups)),
	}
	for _, group := range groupsPage.Groups {
		orgPage.Organizations = append(orgPage.Organizations, Organization{group})
	}
	// hack
	orgPage.pageRes = pageRes{Total: groupsPage.Total, Offset: offset, Limit: limit}
	return orgPage, nil
}
