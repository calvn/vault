package jwt

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (string, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "jwt"
	}

	idToken, ok := m["id_token"]
	if !ok {
		return "", fmt.Errorf("ID token should be provided")
	}

	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := c.Logical().Write(path, map[string]interface{}{
		"id_token": idToken,
	})
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

func (h *CLIHandler) Help() string {
	help := `
The JWT credential provider allows you to authenticate with a signed JWT token.
To use it, specify the "id_token" parameter. The value should be a signed JWT
token. You can leverage JWT tokens with Auth0, or generate your own signed JWT token.

    Example: vault auth -method=jwt id_token=<id_token>

Key/Value Pairs:

    mount=jwt               The mountpoint for the JWT credential provider.
                            Defaults to "jwt"

    id_token=<id_token>     The signed JWT token, usually referred as id_token.
	`

	return strings.TrimSpace(help)
}
