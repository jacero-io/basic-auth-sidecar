package v3

import (
	"context"
	"net/http"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/jacero-io/basic-auth-sidecar/internal/auth"
	"github.com/jacero-io/basic-auth-sidecar/internal/config"
	"github.com/jacero-io/basic-auth-sidecar/internal/ratelimit"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
)

func TestAuthorizationServer_Check(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{
		Auth: struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		}{
			Username: "testuser",
			Password: "testpass",
		},
	}
	authenticator := auth.NewAuthenticator(cfg, logger)
	rateLimiter := ratelimit.NewIPRateLimiter(rate.Limit(1), 1, 1*time.Millisecond, 1*time.Millisecond, authenticator)
	server := New(authenticator, rateLimiter, logger)

	tests := []struct {
		name           string
		request        *authv3.CheckRequest
		expectedStatus codes.Code
		expectedBody   string
	}{
		{
			name: "Valid authentication",
			request: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"authorization": "Basic dGVzdHVzZXI6dGVzdHBhc3M=",
							},
						},
					},
					Source: &authv3.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "192.168.1.1",
								},
							},
						},
					},
				},
			},
			expectedStatus: codes.OK,
			expectedBody:   "",
		},
		{
			name: "Invalid authentication",
			request: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"authorization": "Basic aW52YWxpZDppbnZhbGlk",
							},
						},
					},
					Source: &authv3.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "192.168.1.2",
								},
							},
						},
					},
				},
			},
			expectedStatus: codes.Unauthenticated,
			expectedBody:   "Unauthorized",
		},
		{
			name: "Missing authentication",
			request: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Headers: map[string]string{},
						},
					},
					Source: &authv3.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "192.168.1.3",
								},
							},
						},
					},
				},
			},
			expectedStatus: codes.Unauthenticated,
			expectedBody:   "Unauthorized",
		},
		// {
		// 	name: "Rate limit exceeded",
		// 	request: &authv3.CheckRequest{
		// 		Attributes: &authv3.AttributeContext{
		// 			Request: &authv3.AttributeContext_Request{
		// 				Http: &authv3.AttributeContext_HttpRequest{
		// 					Headers: map[string]string{},
		// 				},
		// 			},
		// 			Source: &authv3.AttributeContext_Peer{
		// 				Address: &core.Address{
		// 					Address: &core.Address_SocketAddress{
		// 						SocketAddress: &core.SocketAddress{
		// 							Address: "192.168.1.4",
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	expectedStatus: codes.PermissionDenied,
		// 	expectedBody:   "Too Many Requests",
		// },
		{
			name:           "Missing attributes",
			request:        &authv3.CheckRequest{},
			expectedStatus: codes.PermissionDenied,
			expectedBody:   "Missing attributes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For the "Rate limit exceeded" test, make two consecutive requests
			if tt.name == "Rate limit exceeded" {
				_, _ = server.Check(context.Background(), tt.request)
				time.Sleep(10 * time.Millisecond) // Wait a bit to ensure rate limiter processes the first request
			}

			response, err := server.Check(context.Background(), tt.request)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if response.Status.Code != int32(tt.expectedStatus) {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, response.Status.Code)
			}

			responseBody := getResponseBody(response)
			if responseBody != tt.expectedBody {
				t.Errorf("Expected body '%s', got '%s'", tt.expectedBody, responseBody)
			}

			// Additional checks for specific scenarios
			switch tt.name {
			case "Valid authentication":
				okResponse, ok := response.HttpResponse.(*authv3.CheckResponse_OkResponse)
				if !ok {
					t.Errorf("Expected OkResponse, got %T", response.HttpResponse)
				} else {
					found := false
					for _, header := range okResponse.OkResponse.Headers {
						if header.Header.Key == "X-Auth-User" && header.Header.Value == "testuser" {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected X-Auth-User header with value 'testuser'")
					}
				}
			case "Missing authentication":
				deniedResponse, ok := response.HttpResponse.(*authv3.CheckResponse_DeniedResponse)
				if !ok {
					t.Errorf("Expected DeniedResponse, got %T", response.HttpResponse)
				} else {
					found := false
					for _, header := range deniedResponse.DeniedResponse.Headers {
						if header.Header.Key == "WWW-Authenticate" && header.Header.Value == `Basic realm="Restricted"` {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected WWW-Authenticate header")
					}
				}
			}
		})
	}
}

func TestAuthorizationServer_Responses(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{
		Auth: struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		}{
			Username: "testuser",
			Password: "testpass",
		},
	}
	authenticator := auth.NewAuthenticator(cfg, logger)
	rateLimiter := ratelimit.NewIPRateLimiter(rate.Limit(1), 1, 5*time.Millisecond, 1*time.Millisecond, authenticator)
	server := New(authenticator, rateLimiter, logger)

	t.Run("okResponse", func(t *testing.T) {
		response := server.okResponse()
		if response.Status.Code != int32(codes.OK) {
			t.Errorf("Expected status code %d, got %d", codes.OK, response.Status.Code)
		}
		okResponse, ok := response.HttpResponse.(*authv3.CheckResponse_OkResponse)
		if !ok {
			t.Fatalf("Expected OkResponse, got %T", response.HttpResponse)
		}
		if len(okResponse.OkResponse.Headers) != 1 {
			t.Errorf("Expected 1 header, got %d", len(okResponse.OkResponse.Headers))
		}
		if okResponse.OkResponse.Headers[0].Header.Key != "X-Auth-User" {
			t.Errorf("Expected X-Auth-User header, got %s", okResponse.OkResponse.Headers[0].Header.Key)
		}
	})

	t.Run("deniedResponse", func(t *testing.T) {
		response := server.deniedResponse(http.StatusTooManyRequests, "Too Many Requests")
		if response.Status.Code != int32(codes.PermissionDenied) {
			t.Errorf("Expected status code %d, got %d", codes.PermissionDenied, response.Status.Code)
		}
		deniedResponse, ok := response.HttpResponse.(*authv3.CheckResponse_DeniedResponse)
		if !ok {
			t.Fatalf("Expected DeniedResponse, got %T", response.HttpResponse)
		}
		if deniedResponse.DeniedResponse.Status.Code != envoy_type.StatusCode(http.StatusTooManyRequests) {
			t.Errorf("Expected HTTP status code %d, got %d", http.StatusTooManyRequests, deniedResponse.DeniedResponse.Status.Code)
		}
		if deniedResponse.DeniedResponse.Body != "Too Many Requests" {
			t.Errorf("Expected body 'Too Many Requests', got '%s'", deniedResponse.DeniedResponse.Body)
		}
	})

	t.Run("unauthorizedResponse", func(t *testing.T) {
		response := server.unauthorizedResponse()
		if response.Status.Code != int32(codes.Unauthenticated) {
			t.Errorf("Expected status code %d, got %d", codes.Unauthenticated, response.Status.Code)
		}
		deniedResponse, ok := response.HttpResponse.(*authv3.CheckResponse_DeniedResponse)
		if !ok {
			t.Fatalf("Expected DeniedResponse, got %T", response.HttpResponse)
		}
		if deniedResponse.DeniedResponse.Status.Code != envoy_type.StatusCode_Unauthorized {
			t.Errorf("Expected HTTP status code %d, got %d", envoy_type.StatusCode_Unauthorized, deniedResponse.DeniedResponse.Status.Code)
		}
		if deniedResponse.DeniedResponse.Body != "Unauthorized" {
			t.Errorf("Expected body 'Unauthorized', got '%s'", deniedResponse.DeniedResponse.Body)
		}
		found := false
		for _, header := range deniedResponse.DeniedResponse.Headers {
			if header.Header.Key == "WWW-Authenticate" && header.Header.Value == `Basic realm="Restricted"` {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected WWW-Authenticate header")
		}
	})
}

func getResponseBody(response *authv3.CheckResponse) string {
	switch httpResponse := response.HttpResponse.(type) {
	case *authv3.CheckResponse_OkResponse:
		return ""
	case *authv3.CheckResponse_DeniedResponse:
		return httpResponse.DeniedResponse.Body
	default:
		return ""
	}
}