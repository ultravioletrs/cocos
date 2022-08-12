package computations

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/clients"
)

type Service interface {
	CreateComputation(ctx context.Context, token string, computation Computation) (string, error)
	ViewComputation(ctx context.Context, token, id string) (Computation, error)
	ListComputations(ctx context.Context, token string, meta PageMetadata) (Page, error)
	UpdateComputation(ctx context.Context, token string, computation Computation) error
	RemoveComputation(ctx context.Context, token, id string) error
}

type service struct {
	repo Repository
	idp  mainflux.IDProvider
	auth clients.AuthServiceClient
}

func NewService(repo Repository, idp mainflux.IDProvider, auth clients.AuthServiceClient) Service {
	return service{
		repo: repo,
		idp:  idp,
		auth: auth,
	}
}

func (svc service) CreateComputation(ctx context.Context, token string, computation Computation) (string, error) {
	id, err := svc.idp.ID()
	if err != nil {
		return "", err
	}
	computation.ID = id
	computation.StartTime = time.Now()
	return svc.repo.Save(ctx, computation)
}

func (svc service) ViewComputation(ctx context.Context, token string, id string) (Computation, error) {
	// Use id as both subject and object as token is currently empty
	// c_add policy is an example of acceptable policy from clients service.
	if err := svc.authorize(ctx, id, id, "c_add"); err != nil {
		return Computation{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	return svc.repo.View(ctx, id)
}

func (svc service) ListComputations(ctx context.Context, token string, meta PageMetadata) (Page, error) {
	return svc.repo.RetrieveAll(ctx, token, meta)
}

func (svc service) UpdateComputation(ctx context.Context, token string, computation Computation) error {
	return svc.repo.Update(ctx, computation)
}

func (svc service) RemoveComputation(ctx context.Context, token string, id string) error {
	// Use id as both subject and object as token is currently empty
	// c_delete policy is an example of acceptable policy from clients service.
	if err := svc.authorize(ctx, id, id, "c_delete"); err != nil {
		return errors.Wrap(errors.ErrAuthentication, err)
	}
	return svc.repo.Delete(ctx, id)
}

func (svc service) authorize(ctx context.Context, subject, object, action string) error {
	req := &clients.AuthorizeReq{
		Sub: subject,
		Obj: object,
		Act: action,
	}
	res, err := svc.auth.Authorize(ctx, req)
	if err != nil {
		return errors.Wrap(errors.ErrAuthorization, err)
	}
	if !res.GetAuthorized() {
		return errors.ErrAuthorization
	}
	return nil
}
