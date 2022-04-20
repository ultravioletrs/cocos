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

func (sdk cSDK) CreateOrganization(o Organization, token string) (string, error) {
	g := mfx.Group{
		Name:        o.Name,
		Description: o.Description,
		ParentID:    o.ParentID,
		Metadata:    o.Metadata,
	}
	return sdk.mf.CreateGroup(g, token)
}

func (sdk cSDK) DeleteOrganization(id, token string) error {
	return sdk.mf.DeleteGroup(id, token)
}

func (sdk cSDK) Assign(memberIDs []string, memberType, organizationID string, token string) error {
	return sdk.mf.Assign(memberIDs, memberType, organizationID, token)
}

func (sdk cSDK) Unassign(token, organizationID string, memberIDs string) error {
	return sdk.mf.Unassign(token, organizationID, memberIDs)
}

func (sdk cSDK) Members(orgId, token string, offset, limit uint64) (mfx.MembersPage, error) {
	return sdk.mf.Members(orgId, token, offset, limit)
}

func (sdk cSDK) Organizations(offset, limit uint64, token string) (OrganizationsPage, error) {
	groupsPage, err := sdk.mf.Groups(offset, limit, token)
	if err != nil {
		return OrganizationsPage{}, err
	}
	var orgPage OrganizationsPage
	for _, group := range groupsPage.Groups {
		orgPage.Organizations = append(orgPage.Organizations, Organization{group})
	}
	// hack
	orgPage.pageRes = pageRes{Total: uint64(len(groupsPage.Groups)), Offset: offset, Limit: limit}
	return orgPage, nil
}

func (sdk cSDK) GetConsortium(orgId string, offset, limit uint64, token string) (OrganizationsPage, error) {
	groupsPage, err := sdk.mf.Parents(orgId, offset, limit, token)
	if err != nil {
		return OrganizationsPage{}, err
	}
	var orgPage OrganizationsPage
	for _, group := range groupsPage.Groups {
		orgPage.Organizations = append(orgPage.Organizations, Organization{group})
	}
	// hack
	orgPage.pageRes = pageRes{Total: uint64(len(groupsPage.Groups)), Offset: offset, Limit: limit}
	return orgPage, nil
}

func (sdk cSDK) GetOrganizationForConsortium(id string, offset, limit uint64, token string) (OrganizationsPage, error) {
	groupsPage, err := sdk.mf.Children(id, offset, limit, token)
	if err != nil {
		return OrganizationsPage{}, err
	}
	var orgPage OrganizationsPage
	for _, group := range groupsPage.Groups {
		orgPage.Organizations = append(orgPage.Organizations, Organization{group})
	}
	// hack
	orgPage.pageRes = pageRes{Total: uint64(len(groupsPage.Groups)), Offset: offset, Limit: limit}
	return orgPage, nil
}

func (sdk cSDK) Organization(orgId, token string) (Organization, error) {
	group, err := sdk.mf.Group(orgId, token)
	if err != nil {
		return Organization{}, err
	}
	return Organization{
		Group: group,
	}, nil
}

func (sdk cSDK) UpdateOrganization(o Organization, token string) error {
	g := mfx.Group{
		ID:          "",
		Name:        "",
		Description: "",
		ParentID:    "",
		Metadata:    map[string]interface{}{},
	}
	return sdk.mf.UpdateGroup(g, token)
}

func (sdk cSDK) Memberships(memberID, token string, offset, limit uint64) (OrganizationsPage, error) {

	groupsPage, err := sdk.mf.Memberships(memberID, token, offset, limit)
	if err != nil {
		return OrganizationsPage{}, err
	}
	var orgPage OrganizationsPage
	for _, group := range groupsPage.Groups {
		orgPage.Organizations = append(orgPage.Organizations, Organization{group})
	}
	// hack
	orgPage.pageRes = pageRes{Total: uint64(len(groupsPage.Groups)), Offset: offset, Limit: limit}
	return orgPage, nil
}
