package sdk

import (
	"crypto/tls"
	"net/http"

	mfx "github.com/mainflux/mainflux/pkg/sdk/go"
)

type ContentType string

const ctJSON ContentType = "application/json"

const computationsEndpoint = "computations"

var _ SDK = (*csdk)(nil)

type SDK interface {
	// CreateComputation registers new thing and returns its id.
	CreateComputation(computation Computation, token string) (string, error)

	// ListComputations returns page of computations.
	ListComputations(token string, offset, limit uint64, name string) (ComputationsPage, error)

	// UpdateThing updates existing thing.
	UpdateComputation(computation Computation, token string) error

	//GetComputation returns computation object by id.
	GetComputation(id, token string) (Computation, error)

	// DeleteComputation removes existing computation.
	DeleteComputation(id, token string) error

	// CreateUser creates a new User in underlying User Management platform.
	CreateUser(token, username, password string) (string, error)

	// CreateOrganization creates new organization and returns its id.
	CreateOrganization(organization Organization, token string) (string, error)

	// DeleteOrganization deletes users organization.
	DeleteOrganization(id, token string) error

	// Organizations returns page of users organizations.
	Organizations(offset, limit uint64, token string) (OrganizationsPage, error)

	// All the consortiums the given organization belongs to.
	OrganizationConsortiums(orgID string, offset, limit uint64, token string) (OrganizationsPage, error)

	// All the organizations that belong to the given consortium.
	ConsortiumOrganizations(consortiumID string, offset, limit uint64, token string) (OrganizationsPage, error)

	// Organization returns users organization object by id.
	Organization(id, token string) (Organization, error)

	// Assign assigns member of member type (thing or user) to a organization.
	Assign(memberIDs []string, memberType, organizationID string, token string) error

	// Unassign removes member from a organization.
	Unassign(token, organizationID string, memberIDs ...string) error

	// Members lists members of a organization.
	Members(organizationID, token string, offset, limit uint64) (mfx.MembersPage, error)

	// Memberships lists organizations for user.
	Memberships(userID, token string, offset, limit uint64) (OrganizationsPage, error)

	// UpdateOrganization updates existing organization.
	UpdateOrganization(organization Organization, token string) error
}

type csdk struct {
	computationsURL string
	client          *http.Client
	mf              mfx.SDK
}

func NewSDK(URL string, mf mfx.SDK) SDK {
	return csdk{
		mf:              mf,
		computationsURL: URL,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (sdk csdk) sendRequest(req *http.Request, token string, ct ContentType) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	if ct != "" {
		req.Header.Add("Content-Type", string(ct))
	}

	return sdk.client.Do(req)
}
