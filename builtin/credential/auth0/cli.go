package auth0

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (string, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "auth0"
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
The Auth0 credential provider allows you to authenticate with GitHub.
To use it, specify the "token" parameter. The value should be a personal access
token for your GitHub account. You can generate a personal access token on your
account settings page on GitHub.

    Example: vault auth -method=github token=<token>

Key/Value Pairs:

    mount=auth0      The mountpoint for the Auth0 credential provider.
                      Defaults to "auth0"

    client_secret=<client_secret>     Client secret used to verify the JWT.
	`

	return strings.TrimSpace(help)
}
