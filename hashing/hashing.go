package hashing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"github.com/monzo/terrors"
	"golang.org/x/crypto/hkdf"
	"io"
)

// GetHashForSMSMessage returns the hash for a given SMS message sent by a given agent to a user with a given public key
func GetHashForSMSMessage(publicKeyString string, agentPrivateKey *ecdsa.PrivateKey, smsMessage []byte) ([]byte, error) {
	publicKey, err := getPublicKeyFromPublicKeyPayload(publicKeyString)
	if err != nil {
		return nil, terrors.Propagate(err)
	}

	sharedSecret, err := ecdhDeriveSecret(agentPrivateKey, publicKey)
	if err != nil {
		return nil, terrors.Propagate(err)
	}

	return deriveHashForSMSMessage(sharedSecret, smsMessage)
}

func deriveHashForSMSMessage(sharedSecret []byte, smsMessageContent []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sharedSecret, nil, smsMessageContent)

	hash := make([]byte, 32)

	_, err := io.ReadFull(kdf, hash)

	if err != nil {
		return nil, terrors.Propagate(err)
	}

	return hash, nil
}

func ecdhDeriveSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	ecdhCurve := elliptic.P384()

	if !ecdhCurve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, terrors.PreconditionFailed(
			terrors.ErrPreconditionFailed,
			"Verified SMS Public Keys should be on curve secp384r1 (elliptic.P384) but this public key is "+
				"not on this curve.",
			map[string]string{
				"public_key.x":          publicKey.X.String(),
				"public_key.y":          publicKey.Y.String(),
				"public_key.curve_name": publicKey.Curve.Params().Name,
			},
		)
	}

	sharedSecret, _ := ecdhCurve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())

	return sharedSecret.Bytes(), nil
}

func getPublicKeyFromPublicKeyPayload(publicKeyPayload string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyPayload)

	if err != nil {
		return nil, terrors.Propagate(err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, terrors.Propagate(err)
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)

	if !ok {
		return nil, terrors.InternalService(terrors.ErrInternalService, "failed to unmarshal into ECDSA", nil)
	}

	return ecdsaPublicKey, nil
}
