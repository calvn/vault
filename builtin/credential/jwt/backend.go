package jwt

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
The JWT credential provider allows authentication via signed JWT tokens.

Users provide a signed JWT, which will be verified against the provided secret key.
Even the though "sub" and "aud" JWT claims are optional fields, the JWT's passed
on to this backend require these fields as a form of user and target identity.
The "aud" is used to map the audience to Vault policies and the "sub" is used to
identify the user since id_tokens can be refreshed for the same end-user.

After enabling the credential provider, use the "config" route to
configure it.
`
