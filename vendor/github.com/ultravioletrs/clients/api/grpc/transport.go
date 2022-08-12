package grpc

import (
	"context"

	kitot "github.com/go-kit/kit/tracing/opentracing"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/mainflux/mainflux/pkg/errors"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/ultravioletrs/clients"
	"github.com/ultravioletrs/clients/internal/apiutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ clients.AuthServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	authorize kitgrpc.Handler
}

// NewServer returns new AuthServiceServer instance.
func NewServer(tracer opentracing.Tracer, svc clients.Service) clients.AuthServiceServer {
	return &grpcServer{
		authorize: kitgrpc.NewServer(
			kitot.TraceServer(tracer, "authorize")(authorizeEndpoint(svc)),
			decodeAuthorizeRequest,
			encodeAuthorizeResponse,
		),
	}
}

func (s *grpcServer) Authorize(ctx context.Context, req *clients.AuthorizeReq) (*clients.AuthorizeRes, error) {
	_, res, err := s.authorize.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*clients.AuthorizeRes), nil
}

func decodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*clients.AuthorizeReq)
	return authReq{Act: req.GetAct(), Obj: req.GetObj(), Sub: req.GetSub()}, nil
}

func encodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(authorizeRes)
	return &clients.AuthorizeRes{Authorized: res.authorized}, nil
}

func encodeError(err error) error {
	switch {
	case errors.Contains(err, nil):
		return nil
	case errors.Contains(err, errors.ErrMalformedEntity),
		err == apiutil.ErrInvalidAuthKey,
		err == apiutil.ErrMissingID,
		err == apiutil.ErrMissingPolicySub,
		err == apiutil.ErrMissingPolicyObj,
		err == apiutil.ErrMissingPolicyAct,
		err == apiutil.ErrMalformedPolicy,
		err == apiutil.ErrMissingPolicyOwner,
		err == apiutil.ErrHigherPolicyRank:
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Contains(err, errors.ErrAuthentication),
		err == apiutil.ErrBearerToken:
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Contains(err, errors.ErrAuthorization):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}
