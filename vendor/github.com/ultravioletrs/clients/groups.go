package clients

import (
	"context"
	"errors"
	"time"
)

const (
	// MaxLevel represents the maximum group hierarchy level.
	MaxLevel = uint64(5)
	// MinLevel represents the minimum group hierarchy level.
	MinLevel = uint64(0)
)

var (
	// ErrAssignToGroup indicates failure to assign member to a group.
	ErrAssignToGroup = errors.New("failed to assign member to a group")

	// ErrUnassignFromGroup indicates failure to unassign member from a group.
	ErrUnassignFromGroup = errors.New("failed to unassign member from a group")

	// ErrMissingParent indicates that parent can't be found
	ErrMissingParent = errors.New("failed to retrieve parent")

	// ErrGroupNotEmpty indicates group is not empty, can't be deleted.
	ErrGroupNotEmpty = errors.New("group is not empty")

	// ErrMemberAlreadyAssigned indicates that members is already assigned.
	ErrMemberAlreadyAssigned = errors.New("member is already assigned")

	// ErrFailedToRetrieveMembers failed to retrieve group members.
	ErrFailedToRetrieveMembers = errors.New("failed to retrieve group members")

	// ErrFailedToRetrieveMembership failed to retrieve memberships
	ErrFailedToRetrieveMembership = errors.New("failed to retrieve memberships")

	// ErrFailedToRetrieveAll failed to retrieve groups.
	ErrFailedToRetrieveAll = errors.New("failed to retrieve all groups")

	// ErrFailedToRetrieveParents failed to retrieve groups.
	ErrFailedToRetrieveParents = errors.New("failed to retrieve all groups")

	// ErrFailedToRetrieveChildren failed to retrieve groups.
	ErrFailedToRetrieveChildren = errors.New("failed to retrieve all groups")
)

// MembersPage contains page related metadata as well as list of members that
// belong to this page.
type MembersPage struct {
	Page
	Members []Client
}

// GroupsPage contains page related metadata as well as list
// of Groups that belong to the page.
type GroupsPage struct {
	Page
	Path      string
	Level     uint64
	ID        string
	Direction int64 // ancestors (-1) or descendants (+1)
	Groups    []Group
}

// Group represents the group of Clients.
// Indicates a level in tree hierarchy. Root node is level 1.
// Path in a tree consisting of group IDs
// Paths are unique per owner.
type Group struct {
	ID          string    `json:"id"`
	OwnerID     string    `json:"owner_id"`
	ParentID    string    `json:"parent_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Metadata    Metadata  `json:"metadata"`
	Level       int       `json:"level"`
	Path        string    `json:"path"`
	Children    []*Group  `json:"children"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GroupRepository specifies a group persistence API.
type GroupRepository interface {
	// Save group.
	Save(ctx context.Context, g Group) (string, error)

	// Update a group.
	Update(ctx context.Context, g Group) error

	// RetrieveByID retrieves group by its id.
	RetrieveByID(ctx context.Context, id string) (Group, error)

	// RetrieveAll retrieves all groups.
	RetrieveAll(ctx context.Context, gm GroupsPage) (GroupsPage, error)

	// Delete a group.
	Delete(ctx context.Context, id string) error
}

// GroupService specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type GroupService interface {
	// CreateGroup creates new  group.
	CreateGroup(ctx context.Context, token string, g Group) (string, error)

	// UpdateGroup updates the group identified by the provided ID.
	UpdateGroup(ctx context.Context, token string, g Group) error

	// ViewGroup retrieves data about the group identified by ID.
	ViewGroup(ctx context.Context, token, id string) (Group, error)

	// ListGroups retrieves groups.
	ListGroups(ctx context.Context, token string, gm GroupsPage) (GroupsPage, error)

	// RemoveGroup removes the group identified with the provided ID.
	RemoveGroup(ctx context.Context, token, id string) error

	// AssignGroupAccessRights adds access rights on thing groups to user group.
	AssignGroupAccessRights(ctx context.Context, token, thingGroupID, userGroupID string) error
}
