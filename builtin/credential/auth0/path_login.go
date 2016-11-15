package auth0

import (
	"encoding/base64"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"id_token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ID token from Auth0",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin,
		},
	}
}

func (b *backend) pathLogin(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	idToken := data.Get("id_token").(string)

	var verifyResp *verifyCredentialsResp
	if verifyResponse, resp, err := b.verifyCredentials(req, idToken); err != nil {
		return nil, err
	} else if resp != nil {
		return resp, nil
	} else {
		verifyResp = verifyResponse
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Policies: verifyResp.Policies,
			Metadata: map[string]string{
				"aud": verifyResp.Aud,
				"sub": verifyResp.Sub,
			},
			InternalData: map[string]interface{}{
				"id_token": idToken,
			},
			DisplayName: verifyResp.Sub,
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
			},
		},
	}, nil
}

func (b *backend) pathLoginRenew(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	var verifyResp *verifyCredentialsResp

	if !policyutil.EquivalentPolicies(verifyResp.Policies, req.Auth.Policies) {
		return nil, fmt.Errorf("policies do not match")
	}

	return framework.LeaseExtend(0, 0, b.System())(req, d)
}

func (b *backend) verifyCredentials(req *logical.Request, token string) (*verifyCredentialsResp, *logical.Response, error) {
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, nil, err
	}

	if config.ClientSecret == "" {
		return nil, logical.ErrorResponse(
			"provide the client secret"), nil
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		decoded, err := base64.URLEncoding.DecodeString(config.ClientSecret)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	})
	if err != nil {
		return nil, nil, err
	}

	// If token is not valid, return error
	if !parsedToken.Valid {
		return nil, nil, fmt.Errorf("token not valid match")
	}

	claims := parsedToken.Claims.(jwt.MapClaims)

	policies, err := b.AudMap.Policies(req.Storage, claims["aud"].(string))
	if err != nil {
		return nil, nil, err
	}

	return &verifyCredentialsResp{
		Aud:      claims["aud"].(string),
		Sub:      claims["sub"].(string),
		Policies: policies,
	}, nil, nil
}

type verifyCredentialsResp struct {
	Aud      string
	Sub      string
	Policies []string
}
