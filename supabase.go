package supabase

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	AuthEndpoint    = "auth/v1"
	AdminEndpoint   = "auth/v1/admin"
	RestEndpoint    = "rest/v1"
	StorageEndpoint = "storage/v1"
)

type Client struct {
	BaseURL string
	// apiKey can be a client API key or a service key
	apiKey     string
	HTTPClient *http.Client
	Admin      *Admin
	Auth       *Auth
}

type ErrorResponse struct {
	Code      int    `json:"code"`
	Message   string `json:"msg"`
	ErrorCode string `json:"error_code"`
}

func (err *ErrorResponse) Error() string {
	jsonBytes, jsonErr := json.Marshal(err)
	if jsonErr != nil {
		return fmt.Sprintf("ErrorResponse{Code: %d, Message: %s, ErrorCode: %s}",
			err.Code, err.Message, err.ErrorCode)
	}
	return string(jsonBytes)
}

func GenericError(err error) *ErrorResponse {
	return &ErrorResponse{
		Code:      500,
		Message:   err.Error(),
		ErrorCode: "generic_error",
	}
}

func NewErrorResponse(code int, message string, errorCode string) *ErrorResponse {
	return &ErrorResponse{
		Code:      code,
		Message:   message,
		ErrorCode: errorCode,
	}
}

func ParseBody[T any](res *http.Response, target *T) error {
	err := json.NewDecoder(res.Body).Decode(target)
	if err != nil {
		return err
	}
	return nil
}

// CreateClient creates a new Supabase client
func CreateClient(baseURL string, supabaseKey string, debug ...bool) *Client {
	client := &Client{
		BaseURL: baseURL,
		apiKey:  supabaseKey,
		Admin:   &Admin{},
		Auth:    &Auth{},
		HTTPClient: &http.Client{
			Timeout: time.Minute,
		},
	}
	client.Admin.client = client
	client.Admin.serviceKey = supabaseKey
	client.Auth.client = client
	return client
}

func injectAuthorizationHeader(req *http.Request, value string) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", value))
}

func (c *Client) sendRequest(req *http.Request) (*http.Response, error) {
	req.Header.Set("apikey", c.apiKey)
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}
