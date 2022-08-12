package clients

import (
	"context"
	"time"
)

// Credentials represent client credentials: its
// "identity" which can be a username, email, generated name;
// and "secret" which can be a password or access token.
type Credentials struct {
	Identity string `json:"identity"` // username or generated login ID
	Secret   string `json:"secret"`   // password or token
}

// Client represents generic Client.
type Client struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Tags        []string    `json:"tags,omitempty"`
	Owner       string      `json:"owner,omitempty"` // nullable
	Credentials Credentials `json:"credentials"`
	Metadata    Metadata    `json:"metadata"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Status      uint16      `json:"status"` // 1 for enabled, 2 for disabled and 3 for all as 0 is usually null
}

// ClientsPage contains page related metadata as well as list
// of Clients that belong to the page.
type ClientsPage struct {
	Page
	Clients []Client
}

// ClientRepository specifies an account persistence API.
type ClientRepository interface {
	// Save persists the client account. A non-nil error is returned to indicate
	// operation failure.
	Save(ctx context.Context, client Client) (string, error)

	// RetrieveByID retrieves client by its unique ID.
	RetrieveByID(ctx context.Context, id string) (Client, error)

	// RetrieveByIdentity retrieves client by its unique credentials
	RetrieveByIdentity(ctx context.Context, identity string) (Client, error)

	// RetrieveAll retrieves all clients.
	RetrieveAll(ctx context.Context, pm Page) (ClientsPage, error)

	// Update updates the client metadata.
	UpdateMetadata(ctx context.Context, client Client) error

	// UpdateCredentials updates password for client with given identity
	UpdateCredentials(ctx context.Context, client Credentials) error

	// ChangeStatus changes client status to enabled or disabled
	ChangeStatus(ctx context.Context, id string, status uint16) error
}

// ClientService specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type ClientService interface {
	// RegisterClient creates new client. In case of the failed registration, a
	// non-nil error value is returned.
	RegisterClient(ctx context.Context, token string, client Client) (string, error)

	// LoginClient authenticates the client given its credentials. Successful
	// authentication generates new access token. Failed invocations are
	// identified by the non-nil error values in the response.
	LoginClient(ctx context.Context, client Client) (string, error)

	// ViewClient retrieves client info for a given client ID and an authorized token.
	ViewClient(ctx context.Context, token, id string) (Client, error)

	// ListClients retrieves clients list for a valid auth token.
	ListClients(ctx context.Context, token string, pm Page) (ClientsPage, error)

	// UpdateClient updates the client's metadata.
	UpdateClient(ctx context.Context, token string, client Client) error

	// EnableClient logically enableds the client identified with the provided ID
	EnableClient(ctx context.Context, token, id string) error

	// DisableClient logically disables the client identified with the provided ID
	DisableClient(ctx context.Context, token, id string) error
}
