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

	// User returns user object.
	User(token string) (User, error)

	// CreateToken receives credentials and returns user token.
	CreateToken(user User) (string, error)

	// UpdateUser updates existing user.
	UpdateUser(user User, token string) error

	// UpdatePassword updates user password.
	UpdatePassword(oldPass, newPass, token string) error

	// CreateConsortium creates new consortium and returns its id.
	CreateConsortium(consortium Consortium, token string) (string, error)

	// Consortiums returns page of users consortiums.
	Consortiums(offset, limit uint64, token string) (ConsortiumsPage, error)

	// All the consortiums the given consortium belongs to.
	OrganizationByConsortiums(conID string, offset, limit uint64, token string) (ConsortiumsPage, error)

	// All the consortiums that belong to the given organization.
	ConsortiumByOrganizations(consortiumID string, offset, limit uint64, token string) (ConsortiumsPage, error)

	// Consortiums returns users consortium object by id.
	Consortium(id, token string) (Consortium, error)

	// Members lists members of a consortium.
	ConsortiumMembers(consortiumID, token string, offset, limit uint64) (mfx.MembersPage, error)

	// Memberships lists consortiums for user.
	ConsortiumMemberships(userID, token string, offset, limit uint64) (ConsortiumsPage, error)

	// UpdateConsortium updates existing consortium.
	UpdateConsortium(consortium Consortium, token string) error

	// DeleteConsortium deletes users consortium.
	DeleteConsortium(id, token string) error

	// Assign assigns member of member type (computation or user or organization) to a consortium.
	AssignToConsortium(memberIDs []string, memberType, consortiumID string, token string) error

	// Unassign removes member from a consortium.
	UnassignFromConsortium(token, consortiumID string, memberIDs ...string) error

	// CreateOrganization creates new organization and returns its id.
	CreateOrganization(organization Organization, token string) (string, error)

	// Organizations returns page of users organizations.
	Organizations(offset, limit uint64, token string) (OrganizationsPage, error)

	// Organization returns users organization object by id.
	Organization(id, token string) (Organization, error)

	// Members lists members of a organization.
	OrganizationMembers(organizationID, token string, offset, limit uint64) (mfx.MembersPage, error)

	// Memberships lists organizations for user.
	OrganizationMemberships(userID, token string, offset, limit uint64) (OrganizationsPage, error)

	// UpdateOrganization updates existing organization.
	UpdateOrganization(organization Organization, token string) error

	// DeleteOrganization deletes users organization.
	DeleteOrganization(id, token string) error

	// Assign assigns member of member type (computation or user or consortium) to a organization.
	AssignToOrganization(memberIDs []string, memberType, organizationID string, token string) error

	// Unassign removes member from a organization.
	UnassignFromOrganization(token, organizationID string, memberIDs ...string) error
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
