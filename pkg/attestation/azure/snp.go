// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"

	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/proto"
)

const maaURL = "https://sharedeus.eus.attest.azure.net"

type AttestationData struct {
	TpmQuote []byte `json:"quote"`
	Token    []byte `json:"data"`
}

type AzureProvider struct {
	TeeNonce  []byte
	VTpmNonce []byte
}

func (a AzureProvider) FetchAttestation() ([]byte, error) {
	token, err := maa.Attest(context.Background(), a.TeeNonce, maaURL, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Azure attestation token: %w", err)
	}

	quote, err := vtpm.FetchQuote(a.VTpmNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch quote: %w", err)
	}

	quoteByte, err := proto.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal quote: %w", err)
	}

	attestationData := &AttestationData{
		TpmQuote: quoteByte,
		Token:    []byte(token),
	}

	attestDataByte, err := json.Marshal(attestationData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation data: %w", err)
	}

	return attestDataByte, nil
}

func (a AzureProvider) VerifyAttestation(report []byte) error {
	var attestationData AttestationData
	err := json.Unmarshal(report, &attestationData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal attestation data: %w", err)
	}

	token := string(attestationData.Token)

	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	jku, jkuOk := unverifiedToken.Header["jku"].(string)
	kid, kidOk := unverifiedToken.Header["kid"].(string)
	if !jkuOk || !kidOk {
		return fmt.Errorf("token is missing jku or kid in header")
	}

	keySet, err := fetchJWKS(jku)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	pubKey, err := getKeyFromJWKS(keySet, kid)
	if err != nil {
		return fmt.Errorf("failed to retrieve public key: %w", err)
	}

	vToken, err := verifyToken(token, pubKey)
	if err != nil {
		return fmt.Errorf("token verification failed: %w", err)
	}

	if !vToken.Valid {
		return fmt.Errorf("token is invalid")
	}

	return nil
}

// verifyToken verifies the JWT using the public key.
func verifyToken(tokenString string, pubKey *rsa.PublicKey) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token is signed with RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	return token, nil
}

func fetchJWKS(jku string) (jwk.Set, error) {
	resp, err := http.Get(jku)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response body: %w", err)
	}

	keySet, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return keySet, nil
}

// getKeyFromJWKS retrieves the public key corresponding to the given kid from the JWKS.
func getKeyFromJWKS(keySet jwk.Set, kid string) (*rsa.PublicKey, error) {
	keys, matched := keySet.LookupKeyID(kid)
	if !matched {
		return nil, fmt.Errorf("no key found for kid: %s", kid)
	}

	var pubKey rsa.PublicKey
	if err := keys.Raw(&pubKey); err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &pubKey, nil
}
