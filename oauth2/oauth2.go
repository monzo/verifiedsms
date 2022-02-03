package oauth2

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/monzo/terrors"
	verified_sms "github.com/monzo/verifiedsms"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"net/http"
)

const (
	Scope = "https://www.googleapis.com/auth/verifiedsms"
)

// GetHttpClient returns a *http.Client which performs requests using the identity of the verified_sms.Partner
// service account
func GetHttpClient(ctx context.Context, partner verified_sms.Partner) (*http.Client, error) {
	serviceAccount := serviceAccountDetails{}
	err := json.Unmarshal([]byte(partner.ServiceAccountJSONFile), &serviceAccount)

	if err != nil {
		return nil, terrors.Propagate(err)
	}

	block, _ := pem.Decode([]byte(serviceAccount.PrivateKeyPEM))

	config := &jwt.Config{
		Email:      serviceAccount.ClientEmail,
		PrivateKey: block.Bytes,
		Scopes: []string{
			Scope,
		},
		TokenURL: google.JWTTokenURL,
	}

	return config.Client(ctx), nil
}

type serviceAccountDetails struct {
	PrivateKeyPEM string `json:"private_key"`
	ClientEmail   string `json:"client_email"`
}
