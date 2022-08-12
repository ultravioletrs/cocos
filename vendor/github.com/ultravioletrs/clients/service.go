package clients

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/clients/internal/apiutil"
)

const (
	// 1 for enabled, 2 for disabled and 3 for all as 0 is usually null
	EnabledStatusKey    = 1
	DisabledStatusKey   = 2
	AllClientsStatusKey = 3
)

var (
	// ErrEnableClient indicates error in enabling client
	ErrEnableClient = errors.New("failed to enable client")

	// ErrDisableClient indicates error in disabling client
	ErrDisableClient = errors.New("failed to disable client")

	errStatusAlreadyAssigned = errors.New("status already assigned")
)

// Service unites Clients and Group services.
type Service interface {
	ClientService
	GroupService
	PolicyService
}

type service struct {
	clients    ClientRepository
	groups     GroupRepository
	policies   PolicyRepository
	idProvider mainflux.IDProvider
}

// NewService returns a new Clients service implementation.
func NewService(c ClientRepository, g GroupRepository, p PolicyRepository, idp mainflux.IDProvider) Service {
	return service{
		clients:    c,
		groups:     g,
		policies:   p,
		idProvider: idp,
	}
}

func (svc service) RegisterClient(ctx context.Context, token string, cli Client) (string, error) {
	id, err := svc.idProvider.ID()
	if err != nil {
		return "", err
	}
	if cli.Status == 0 {
		cli.Status = 1
	}
	cli.ID = id
	cli.CreatedAt = time.Now()
	cli.UpdatedAt = cli.CreatedAt
	return svc.clients.Save(ctx, cli)
}

func (svc service) LoginClient(ctx context.Context, cli Client) (string, error) {
	panic("unimplemented")
}

func (svc service) ViewClient(ctx context.Context, token string, id string) (Client, error) {
	return svc.clients.RetrieveByID(ctx, id)
}

func (svc service) ListClients(ctx context.Context, token string, pm Page) (ClientsPage, error) {
	return svc.clients.RetrieveAll(ctx, pm)
}

func (svc service) UpdateClient(ctx context.Context, token string, cli Client) error {
	// We assume token has client_id
	client := Client{
		ID:       token,
		Metadata: cli.Metadata,
	}
	return svc.clients.UpdateMetadata(ctx, client)
}

func (svc service) EnableClient(ctx context.Context, token, id string) error {
	if err := svc.changeStatus(ctx, token, id, EnabledStatusKey); err != nil {
		return errors.Wrap(ErrDisableClient, err)
	}
	return nil
}

func (svc service) DisableClient(ctx context.Context, token, id string) error {
	if err := svc.changeStatus(ctx, token, id, DisabledStatusKey); err != nil {
		return errors.Wrap(ErrDisableClient, err)
	}
	return nil
}

func (svc service) changeStatus(ctx context.Context, token, id string, status uint16) error {
	dbClient, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return err
	}
	if dbClient.Status == status {
		return errStatusAlreadyAssigned
	}

	return svc.clients.ChangeStatus(ctx, id, status)
}
func (svc service) CreateGroup(ctx context.Context, token string, g Group) (string, error) {
	id, err := svc.idProvider.ID()
	if err != nil {
		return "", err
	}
	g.ID = id
	g.CreatedAt = time.Now()
	return svc.groups.Save(ctx, g)
}

func (svc service) ViewGroup(ctx context.Context, token string, id string) (Group, error) {
	return svc.groups.RetrieveByID(ctx, id)
}

func (svc service) ListGroups(ctx context.Context, token string, gm GroupsPage) (GroupsPage, error) {
	return svc.groups.RetrieveAll(ctx, gm)
}

func (svc service) ListMembers(ctx context.Context, token, groupID string, gm GroupsPage) (ClientsPage, error) {
	panic("unimplemented")
}

func (svc service) UpdateGroup(ctx context.Context, token string, g Group) error {
	g.UpdatedAt = time.Now()
	return svc.groups.Update(ctx, g)
}

func (svc service) RemoveGroup(ctx context.Context, token, id string) error {
	return svc.groups.Delete(ctx, id)
}

func (svc service) AssignGroupAccessRights(ctx context.Context, token, thingGroupID string, userGroupID string) error {
	panic("unimplemented")
}

func (svc service) Authorize(ctx context.Context, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return nil
}
func (svc service) UpdatePolicy(ctx context.Context, token string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.checkActionRank(ctx, token, p); err != nil {
		return err
	}
	p.UpdatedAt = time.Now()
	return svc.policies.Update(ctx, p)
}

func (svc service) AddPolicy(ctx context.Context, token string, p Policy) error {
	// We assume token has client_id
	if err := p.Validate(); err != nil {
		return err
	}
	page, err := svc.policies.Retrieve(ctx, Page{Subject: p.Subject, Object: p.Object})
	if err != nil {
		return err
	}
	if len(page.Policies) != 0 {
		return svc.policies.Update(ctx, p)
	}
	if err := svc.checkActionRank(ctx, token, p); err != nil {
		return err
	}
	p.OwnerID = token
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	return svc.policies.Save(ctx, p)
}

func (svc service) DeletePolicy(ctx context.Context, token string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.checkActionRank(ctx, token, p); err != nil {
		return err
	}
	return svc.policies.Delete(ctx, p)
}

func (svc service) ListPolicy(ctx context.Context, token string, pm Page) (PolicyPage, error) {
	if err := pm.Validate(); err != nil {
		return PolicyPage{}, err
	}
	page, err := svc.policies.Retrieve(ctx, pm)
	if err != nil {
		return PolicyPage{}, err
	}
	return page, err
}

// checkActionRank check if an action is in the provide list of actions
func (svc service) checkActionRank(ctx context.Context, token string, p Policy) error {
	// we assume token to be user_id tentatively before adding authentication
	page, err := svc.policies.Retrieve(ctx, Page{Subject: token, Object: p.Object})
	if err != nil {
		return err
	}
	if len(page.Policies) != 0 {
		for _, a := range p.Actions {
			var found = false
			for _, v := range page.Policies[0].Actions {
				if v == a {
					found = true
					break
				}
			}
			if !found {
				return apiutil.ErrHigherPolicyRank
			}
		}
	}
	return nil

}
