package v3

import (
	"context"
	"net/http"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/jacero-io/basic-auth-sidecar/internal/auth"
	"github.com/jacero-io/basic-auth-sidecar/internal/ratelimit"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

type AuthorizationServer struct {
    authenticator *auth.Authenticator
    rateLimiter   *ratelimit.IPRateLimiter
    logger        *zap.Logger
}

func New(authenticator *auth.Authenticator, rateLimiter *ratelimit.IPRateLimiter, logger *zap.Logger) *AuthorizationServer {
    return &AuthorizationServer{
        authenticator: authenticator,
        rateLimiter:   rateLimiter,
        logger:        logger,
    }
}

func (a *AuthorizationServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
    a.logger.Debug("Received authorization check request")

    if req.Attributes == nil || req.Attributes.Request == nil || req.Attributes.Request.Http == nil {
        return a.deniedResponse(http.StatusBadRequest, "Missing attributes"), nil
    }

    headers := req.Attributes.Request.Http.Headers
    remoteIP := req.Attributes.Source.Address.GetSocketAddress().GetAddress()

    authHeader, ok := headers["authorization"]
    if !ok {
        return a.handleUnauthenticatedRequest(remoteIP)
    }

    authenticated, err := a.authenticator.Authenticate(authHeader)
    if err != nil {
        a.logger.Error("Authentication error", zap.Error(err))
        return a.handleFailedAuthentication(remoteIP, authHeader)
    }

    if !authenticated {
        return a.handleFailedAuthentication(remoteIP, authHeader)
    }

    return a.okResponse(), nil
}

func (a *AuthorizationServer) handleUnauthenticatedRequest(remoteIP string) (*authv3.CheckResponse, error) {
    if !a.rateLimiter.Allow(remoteIP, "") {
        a.logger.Warn("Rate limit exceeded for unauthenticated request", zap.String("ip", remoteIP))
        return a.deniedResponse(http.StatusTooManyRequests, "Too Many Requests"), nil
    }
    return a.unauthorizedResponse(), nil
}

func (a *AuthorizationServer) handleFailedAuthentication(remoteIP, authHeader string) (*authv3.CheckResponse, error) {
    if !a.rateLimiter.Allow(remoteIP, authHeader) {
        a.logger.Warn("Rate limit exceeded for failed authentication", zap.String("ip", remoteIP))
        return a.deniedResponse(http.StatusTooManyRequests, "Too Many Requests"), nil
    }
    return a.unauthorizedResponse(), nil
}

func (a *AuthorizationServer) okResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "X-Auth-User",
							Value: a.authenticator.GetUsername(),
						},
					},
				},
			},
		},
	}
}

func (a *AuthorizationServer) deniedResponse(statusCode int32, body string) *authv3.CheckResponse {
    return &authv3.CheckResponse{
        Status: &status.Status{
            Code: int32(codes.PermissionDenied),
        },
        HttpResponse: &authv3.CheckResponse_DeniedResponse{
            DeniedResponse: &authv3.DeniedHttpResponse{
                Status: &envoy_type.HttpStatus{
                    Code: envoy_type.StatusCode(statusCode),
                },
                Body: body,
            },
        },
    }
}

func (a *AuthorizationServer) unauthorizedResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.Unauthenticated),
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Unauthorized,
				},
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "WWW-Authenticate",
							Value: `Basic realm="Restricted"`,
						},
					},
				},
				Body: "Unauthorized",
			},
		},
	}
}