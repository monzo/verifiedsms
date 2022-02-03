package verifiedsms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"github.com/monzo/terrors"
	data_munging "github.com/monzo/verifiedsms/data-munging"
	"github.com/monzo/verifiedsms/hashing"
	"github.com/monzo/verifiedsms/oauth2"
	"net/http"
)

const (
	ApiGetPublicKeysUrl = "https://verifiedsms.googleapis.com/v1/enabledUserKeys:batchGet"
	ApiSubmitHashesUrl  = "https://verifiedsms.googleapis.com/v1/messages:batchCreate"
	ContentTypeHeader   = "application/json"
	UserAgentHeader     = "monzo/verifiedsms"
)

type Partner struct {
	// The JSON keys for a service account that will make requests to create messages and enable user keys as the
	// Verified SMS partner
	ServiceAccountJSONFile string
}

type Agent struct {
	// The ID of the Verified SMS agent to use
	ID string

	// The private key of the Verified SMS agent to use
	PrivateKey *ecdsa.PrivateKey
}

// MarkSMSAsVerified marks a given SMS as verified for a given end users phone number
// agent is a VerifiedSMSAgent that the message will appear to be sent from
// smsMessage is the content of the message to be verified
// Returns a boolean to indicate whether the SMS was verified, this will be false if there were no errors but the users'
// device just doesn't support Verified SMS
// An error will be returned if we couldn't mark the SMS as Verified and we aren't sure whether the user is on
// Verified SMS
func (partner Partner) MarkSMSAsVerified(ctx context.Context, phoneNumber string, agent *Agent, smsMessage string) (bool, error) {
	publicKeys, err := partner.GetPhoneNumberPublicKeys(ctx, phoneNumber)
	if err != nil {
		return false, terrors.Propagate(err)
	}

	if len(publicKeys) == 0 {
		return false, nil
	}

	var messagesToGoogle []messageSubmissionToGoogle

	smsMessages := data_munging.GetAllIterationsOfSMSMessage(smsMessage)

	for _, publicKey := range publicKeys {
		for _, smsMessageEntry := range smsMessages {
			hash, err := hashing.GetHashForSMSMessage(publicKey, agent.PrivateKey, []byte(smsMessageEntry))
			if err != nil {
				return false, terrors.Propagate(err)
			}

			messagesToGoogle = append(messagesToGoogle, messageSubmissionToGoogle{
				Hash:    base64.StdEncoding.EncodeToString(hash),
				AgentId: agent.ID,
			})
		}
	}

	requestStruct := batchSubmitRequest{
		Messages: messagesToGoogle,
	}

	requestBody, err := json.Marshal(requestStruct)
	if err != nil {
		return false, terrors.Propagate(err)
	}

	request, err := http.NewRequest("POST", ApiSubmitHashesUrl, bytes.NewReader(requestBody))
	if err != nil {
		return false, terrors.Propagate(err)
	}

	request.Header.Set("Content-Type", ContentTypeHeader)
	request.Header.Set("User-Agent", UserAgentHeader)

	client, err := oauth2.GetHttpClient(ctx, partner.ServiceAccountJSONFile)
	if err != nil {
		return false, terrors.Propagate(err)
	}

	httpResponse, err := client.Do(request)
	if err != nil {
		return false, terrors.Propagate(err)
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		return false, terrors.InternalService(
			terrors.ErrInternalService,
			"bad response from Google: "+httpResponse.Status,
			nil,
		)
	}

	return true, nil
}

// GetPhoneNumberPublicKeys gets the public keys for a given phone number from the Verified SMS service and returns them
// as a slice of strings
func (partner Partner) GetPhoneNumberPublicKeys(ctx context.Context, phoneNumber string) ([]string, error) {
	requestBody, err := json.Marshal(map[string][]string{
		"phoneNumbers": {
			phoneNumber,
		},
	})

	if err != nil {
		return nil, terrors.Propagate(err)
	}

	request, err := http.NewRequest("POST", ApiGetPublicKeysUrl, bytes.NewReader(requestBody))

	if err != nil {
		return nil, terrors.Propagate(err)
	}

	request.Header.Set("Content-Type", ContentTypeHeader)
	request.Header.Set("User-Agent", UserAgentHeader)

	client, err := oauth2.GetHttpClient(ctx, partner.ServiceAccountJSONFile)
	if err != nil {
		return nil, terrors.Propagate(err)
	}

	httpResponse, err := client.Do(request)
	if err != nil {
		return nil, terrors.Propagate(err)
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		return nil, terrors.InternalService(
			terrors.ErrInternalService,
			"bad response from Google: "+httpResponse.Status,
			nil,
		)
	}

	response := verifiedSMSResponse{}

	err = json.NewDecoder(httpResponse.Body).Decode(&response)

	if err != nil {
		return nil, terrors.Propagate(err)
	}

	var publicKeys []string

	for _, keys := range response.UserKeys {
		if keys.PhoneNumber == phoneNumber {
			publicKeys = append(publicKeys, keys.PublicKey)
		}
	}

	return publicKeys, nil
}

type verifiedSMSResponse struct {
	UserKeys []verifiedSMSResponseUserKeys `json:"userKeys"`
}

type verifiedSMSResponseUserKeys struct {
	PhoneNumber string `json:"phoneNumber"`
	PublicKey   string `json:"publicKey"`
}

type messageSubmissionToGoogle struct {
	Hash    string `json:"hash"`
	AgentId string `json:"agentId"`
}

type batchSubmitRequest struct {
	Messages []messageSubmissionToGoogle `json:"messages"`
}
