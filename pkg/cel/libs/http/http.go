package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/kyverno/kyverno/pkg/tracing"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type ClientInterface interface {
	Do(*http.Request) (*http.Response, error)
}

type contextImpl struct {
	client ClientInterface
}

func NewHTTP(client ClientInterface) ContextInterface {
	if client == nil {
		client = http.DefaultClient
	}
	return &contextImpl{
		client: client,
	}
}

// Get performs an HTTP GET request and returns the response.
// The response includes a statusCode field for evaluating HTTP status codes.
//
// For map responses, statusCode is merged into the response body:
//   {"data": "value", "statusCode": 200}
//
// For non-map responses (arrays, primitives), the response is wrapped:
//   {"body": [...], "statusCode": 200}
//
// Network errors (connection failures, timeouts) return an error and fail
// policy evaluation. HTTP errors (4xx, 5xx) return the response object
// with the corresponding status code, allowing policies to handle them.
//
// Example usage in CEL:
//   variables.response.statusCode == 200
//   variables.response.statusCode == 404
//   variables.response.data
func (r *contextImpl) Get(url string, headers map[string]string) (any, error) {
	req, err := http.NewRequestWithContext(context.TODO(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(r.client, req)
}

// Post performs an HTTP POST request and returns the response.
// The response includes a statusCode field for evaluating HTTP status codes.
//
// For map responses, statusCode is merged into the response body:
//   {"result": "success", "statusCode": 201}
//
// For non-map responses (arrays, primitives), the response is wrapped:
//   {"body": [...], "statusCode": 200}
//
// Network errors (connection failures, timeouts) return an error and fail
// policy evaluation. HTTP errors (4xx, 5xx) return the response object
// with the corresponding status code, allowing policies to handle them.
//
// Example usage in CEL:
//   variables.response.statusCode == 201
//   variables.response.statusCode != 404
//   variables.response.result
func (r *contextImpl) Post(url string, data any, headers map[string]string) (any, error) {
	body, err := buildRequestData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request data: %w", err)
	}
	req, err := http.NewRequestWithContext(context.TODO(), "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(r.client, req)
}

func (r *contextImpl) executeRequest(client ClientInterface, req *http.Request) (any, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse body regardless of status code
	var body any
	if resp.Body != nil {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			// If body parsing fails, set body to nil but continue
			// This allows policies to check statusCode even when body is invalid
			body = nil
		}
	}

	// Add statusCode to the response in a backwards-compatible way
	// If body is a map, add statusCode to it (preserves existing field access)
	if bodyMap, ok := body.(map[string]any); ok {
		bodyMap["statusCode"] = resp.StatusCode
		return bodyMap, nil
	}

	// If body is not a map (array, primitive, or nil), wrap it
	// This ensures statusCode is always accessible
	return map[string]any{
		"body":       body,
		"statusCode": resp.StatusCode,
	}, nil
}

func (r *contextImpl) Client(caBundle string) (ContextInterface, error) {
	if caBundle == "" {
		return r, nil
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(caBundle)); !ok {
		return nil, fmt.Errorf("failed to parse PEM CA bundle for APICall")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	return &contextImpl{
		client: &http.Client{
			Transport: tracing.Transport(transport, otelhttp.WithFilter(tracing.RequestFilterIsInSpan)),
		},
	}, nil
}

func buildRequestData(data any) (io.Reader, error) {
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(data); err != nil {
		return nil, fmt.Errorf("failed to encode HTTP POST data %v: %w", data, err)
	}
	return buffer, nil
}
