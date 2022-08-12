package clients

import (
	"context"
	"time"

	"github.com/ultravioletrs/clients/internal/apiutil"
)

// policyTypes contains a list of the available policy types currently supported
var policyTypes = []string{"c_delete", "c_update", "c_add", "c_list", "g_delete", "g_update", "g_add", "g_list", "m_write", "m_read", "d_delete", "d_update", "d_add", "d_list"}

// Policy represents an argument struct for making a policy related function calls.
type Policy struct {
	OwnerID   string    `json:"owner_id"`
	Subject   string    `json:"subject"`
	Object    string    `json:"object"`
	Actions   []string  `json:"actions"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PolicyPage contains a page of policies.
type PolicyPage struct {
	Page
	Policies []Policy
}

// PolicyRepository specifies an account persistence API.
type PolicyRepository interface {
	// Save creates a policy for the given Subject, so that, after
	// Save, `Subject` has a `relation` on `group_id`. Returns a non-nil
	// error in case of failures.
	Save(ctx context.Context, p Policy) error

	// Update updates the policy type.
	Update(ctx context.Context, p Policy) error

	// Retrieve retrieves policy for a given input.
	Retrieve(ctx context.Context, pm Page) (PolicyPage, error)

	// Delete deletes the policy
	Delete(ctx context.Context, p Policy) error
}

// PolicyService represents a authorization service. It exposes
// functionalities through `auth` to perform authorization.
type PolicyService interface {
	// Authorize checks authorization of the given `subject`. Basically,
	// Authorize verifies that Is `subject` allowed to `relation` on
	// `object`. Authorize returns a non-nil error if the subject has
	// no relation on the object (which simply means the operation is
	// denied).
	Authorize(ctx context.Context, p Policy) error

	// AddPolicy creates a policy for the given subject, so that, after
	// AddPolicy, `subject` has a `relation` on `object`. Returns a non-nil
	// error in case of failures.
	AddPolicy(ctx context.Context, token string, p Policy) error

	// UpdatePolicy updates policies based on the given policy structure.
	UpdatePolicy(ctx context.Context, token string, p Policy) error

	// ListPolicy lists policies based on the given policy structure.
	ListPolicy(ctx context.Context, token string, pm Page) (PolicyPage, error)

	// DeletePolicy removes a policy.
	DeletePolicy(ctx context.Context, token string, p Policy) error
}

// Validate returns an error if policy representation is invalid.
func (p Policy) Validate() error {
	if p.Subject == "" {
		return apiutil.ErrMissingPolicySub
	}
	if p.Object == "" {
		return apiutil.ErrMissingPolicyObj
	}
	if len(p.Actions) == 0 {
		return apiutil.ErrMissingPolicyAct
	}
	for _, p := range p.Actions {
		if ok := ValidateAction(p); !ok {
			return apiutil.ErrMissingPolicyAct
		}
	}
	return nil
}

// ValidateAction check if the action is in policies
func ValidateAction(act string) bool {
	for _, v := range policyTypes {
		if v == act {
			return true
		}
	}
	return false

}
