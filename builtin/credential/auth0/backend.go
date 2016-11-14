package auth0

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	return Backend().Setup(conf)
}

func Backend() *backend {
	var b backend
	b.AudMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "aud",
		},
		DefaultKey: "default",
	}

	allPaths := b.AudMap.Paths()

	b.Backend = &framework.Backend{
		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},

		Paths: append([]*framework.Path{
			pathConfig(&b),
			pathLogin(&b),
		}, allPaths...),

		AuthRenew: b.pathLoginRenew,
	}

	return &b
}

type backend struct {
	*framework.Backend

	AudMap *framework.PolicyMap
}

const backendHelp = `
The auth0 credential provider allows authentication via JWT ID tokens.

Configuration of the server is done through the "config". Authentication is then done
by suppying the two fields for "login".
`
