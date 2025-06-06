package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	log "log/slog"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/valkey-io/valkey-go"
)

const cacheExpirySeconds = 120

func NewAuth(valkeyClient valkey.Client, scope, issuer string) *Auth {
	return &Auth{
		valkeyClient:       valkeyClient,
		requiredScope:      scope,
		requiredIssuer:     issuer,
		jwksEndpoint:       fmt.Sprintf("%s/.well-known/jwks.json", issuer),
		cacheExpirySeconds: cacheExpirySeconds,
	}
}

type Auth struct {
	valkeyClient       valkey.Client
	requiredScope      string
	requiredIssuer     string
	jwksEndpoint       string
	cacheExpirySeconds int64
}
type jwksResult struct {
	Keys []map[string]any `json:"keys"`
}

func (s *Auth) WithAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractBearerToken(r)
		if tokenStr == "" {
			http.Error(w, "Missing auth token header", http.StatusUnauthorized)
			return
		}

		// Parse JWT and validate signature
		parser := jwt.NewParser(jwt.WithIssuer(s.requiredIssuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		token, err := parser.Parse(tokenStr, s.keyFunc)
		if err != nil {
			// Do not expose error details to the end user to avoid leakage, just log
			log.Error("JWT auth token validation error", "error", err)
			http.Error(w, "Invalid auth token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}

		// Check for custom scope
		if !hasScope(claims, s.requiredScope) {
			http.Error(w, "Missing required JWT scope", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func hasScope(claims jwt.MapClaims, expected string) bool {
	scopeStr, ok := claims["scope"].(string)
	if !ok {
		return false
	}

	scopes := strings.Split(scopeStr, " ")
	for _, s := range scopes {
		if s == expected {
			return true
		}
	}
	return false
}

func (s *Auth) keyFunc(token *jwt.Token) (interface{}, error) {
	// Get the key ID from user-supplied JWT
	keyId, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid not set in the JWT header")
	}

	// Check if the key is in the cache
	ctx := context.Background()
	modulusStr, exponentStr, err := s.getCacheKey(ctx, keyId)
	if err != nil {
		return nil, fmt.Errorf("unable to get key from cache: %w", err)
	}

	// Cache hit
	if modulusStr != "" && exponentStr != "" {
		return parseRSAPublicKey(modulusStr, exponentStr)
	}

	// Cache miss. Retrieve from the JWKS URL
	keys, err := s.getJWKSEndpoint()
	if err != nil {
		return nil, fmt.Errorf("problem getting JWKS endpoint: %w", err)
	}

	// Find key which has signed the user's JWT in the JWKS keys
	keyModulus, keyExponent, err := s.findKeyID(keyId, keys)
	if err != nil {
		return nil, fmt.Errorf("finding key in JWKS: %w", err)
	}

	// Add the key to the cache with a TTL
	// There is a proposed function that is in the library but not in the server yet:
	// It could be used to consolidate this function in the future: https://pkg.go.dev/github.com/valkey-io/valkey-go@v1.0.60/internal/cmds#Builder.Hsetex
	if err = s.setCacheKey(ctx, keyModulus, keyExponent, keyId); err != nil {
		return nil, fmt.Errorf("setting cache key: %w", err)
	}

	return parseRSAPublicKey(keyModulus, keyExponent)
}

func (s *Auth) getJWKSEndpoint() (jwksResult, error) {
	log.Info("Fetching JWKS keys", "endpoint", s.jwksEndpoint)

	resp, err := http.Get(s.jwksEndpoint)
	if err != nil {
		return jwksResult{}, fmt.Errorf("unable to connect to JWKS endpoint: %w", err)
	}
	defer func(body io.ReadCloser) {
		err := body.Close()
		if err != nil {
			log.Error("Problem closing HTTP response body", "error", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return jwksResult{}, fmt.Errorf("got non-200 response (HTTP %d) from JWKS endpoint", resp.StatusCode)
	}

	resultBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return jwksResult{}, fmt.Errorf("reading HTTP response body: %w", err)
	}

	var keys io.Reader
	keys = bytes.NewBuffer(resultBytes)

	result := jwksResult{}

	if err = json.NewDecoder(keys).Decode(&result); err != nil {
		return jwksResult{}, fmt.Errorf("unable to decode JWKS payload: %w", err)
	}

	return result, nil
}

func (s *Auth) findKeyID(keyID string, jwks jwksResult) (string, string, error) {
	for _, key := range jwks.Keys {
		if kid, ok := key["kid"].(string); ok && kid == keyID {
			keyModulus, okN := key["n"].(string)
			keyExponent, okE := key["e"].(string)
			if !okN || !okE {
				return "", "", fmt.Errorf("invalid jwk: missing n or e")
			}

			return keyModulus, keyExponent, nil
		}
	}

	return "", "", fmt.Errorf("invalid jwk: missing n or e")
}

func (s *Auth) getCacheKey(ctx context.Context, keyID string) (string, string, error) {
	valKeyResult, err := s.valkeyClient.Do(ctx, s.valkeyClient.B().Hmget().Key(keyID).Field("modulus", "exponent").Build()).ToArray()
	if err != nil {
		return "", "", fmt.Errorf("error whilst querying the cache: %w", err)
	}

	// Unexpected result, return as a cache miss
	if len(valKeyResult) != 2 || valKeyResult[0].IsNil() || valKeyResult[1].IsNil() {
		return "", "", nil
	}

	log.Info("Cache hit: found key", "keyID", keyID)

	modulusStr, err := valKeyResult[0].ToString()
	if err != nil {
		return "", "", fmt.Errorf("error converting modulus to a string: %w", err)
	}

	exponentStr, err := valKeyResult[1].ToString()
	if err != nil {
		return "", "", fmt.Errorf("error converting exponent to a string: %w", err)
	}

	return modulusStr, exponentStr, nil
}

func (s *Auth) setCacheKey(ctx context.Context, modulus, exponent, keyID string) error {
	_, err := s.valkeyClient.Do(ctx, s.valkeyClient.B().Hset().
		Key(keyID).
		FieldValue().FieldValue("modulus", modulus).FieldValue("exponent", exponent).
		Build()).ToInt64()
	if err != nil {
		return fmt.Errorf("unable to set key %s in cache: %w", keyID, err)
	}

	_, err = s.valkeyClient.Do(ctx, s.valkeyClient.B().Expire().
		Key(keyID).
		Seconds(s.cacheExpirySeconds).
		Build()).ToInt64()
	if err != nil {
		return fmt.Errorf("unable to set TTL on key %s in cache: %w", keyID, err)
	}

	log.Info("Added key to cache with TTL", "keyID", keyID, "TTL", s.cacheExpirySeconds)

	return nil
}

func parseRSAPublicKey(keyModulus, keyExponent string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(keyModulus)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n (modulus) from the public key: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(keyExponent)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e (exponent) from the public key: %w", err)
	}

	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}
