package jwtauth_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/OpenCHAMI/jwtauth/v5"
	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	TokenAuthHS256 *jwtauth.JWTAuth
	TokenSecret    = []byte("secretpass")

	TokenAuthRS256 *jwtauth.JWTAuth

	PrivateKeyRS256String = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuhIZN1pb0S/0PvCZvzW3fBS+/5Elg1ACt8pnLOQnye/dKssH
GRxihg+hjoVXbahPk2cM/rvoXu0SWtc864g4Jcu7UoyQdj0SucaLuwMxhJW00d/2
MYBqy9l1Vbqiveo+f4H+WwxVpKhpOj5UD1idaxZfgLsGLd1Kk7qYkT5wOBxvC8mf
ahZJaYXWr/taMH0sWYrJ9rCy9g54fG4LENq8raLr/vMOkVFtJIR4cuPgd9uL0kPt
EKVsQOK1WpaBpZXZiS3f18bkMXVksnhlFv5WEta8DoI1F3KMUo+Lz/M4FNS2PWnU
RoutTy9REO7VDJj9Sge/Ep4CuIWsBoTp9361oQIDAQABAoIBAAbF8CJMUR2QJPBS
Foyn7kwPXsUDkfWh2Nl7Hg6bpwmiKD89qP5cYsc9xCwhlTVGDFCBrq7KpQqoj1Oc
dGif+qhAjmryuDL/peH6lN1LwFaS0wRVRltWsPyG588lNjWa1GfUke9bR3ZRFZSD
zpBI8eEDLVqMpEzQ2n0+bH2UA+Z87Wafr+wKTKGTgxgre7vaRO0+Nv6PEafS8fDr
5H3gOK/94sr7NPZiTrflvV8+F44APynYKhZiY+vql05pDoaMw/QZgoPItd6M3oQ4
GlwWWp2nwcBJl/8HFhNqC/X9YXo5nqNMfY6pdzAsYH/bFgsswrTRmtwxETwz/AAx
IBOeR/kCgYEA/uEZmQjRyU5uNkJ1sJZC+PCeXUh3t0+qk7oPRzriNUoAcpyUGNGc
E3uaSuVEBqKwL4ttR+fHpH0oqr6Lo5ha1dboB9A7CBSTWgTHfCA7xz3oQeVRyBsZ
eIXPXwXWzKzFhRHNKRVnarwVC0TneyBaPNhXhKZCSk70JofJcz63dVkCgYEAuuOL
oPK6gkrNgt8S7qkFtb/NWK2gJsJ0SJJCf47ou/KrlA0uQsz47kZXl1lJwcIyaWz9
9Fy2aynzdHTqgc7MgyCar75WTzN1nJ+KTAfCTt/WTWh6ZgZAdy6CgySQISMTZ771
+p/zFpOGXkrOO7NdhaS4ifYccUcIECWO3H32EYkCgYEA2pYYSuuKZzeRQ415u2kS
pMZPOrcknJyBMNJXugHg8Ey315M7W5GgZgESEPtQfNRXf1726Lz5tbL1BoIF5daK
yGvXcKP/jG2A9am1n1lRiw0nvCO8IH5FONyhPOAYGE5v0zCyH3LQz3PgJFsCntDf
MuFjJUsk/O97afP4K5L06XkCgYB9k0/LAc4YpjKY8VNDUgcoLIzKPUATSy3fZYeR
NnFjeJeZj5G6CQhq8pEAfVp1+wrsk/PAMlvQfgu8AKNiPZZltY667+YGqckpSHog
xEXnwbe5o646x5ChhHrlq7e8zFjJqSKXGMq6LL5otVMGAmug1SG6cciCxPvB/bqU
pX6mIQKBgQCDT2WJzGvy40z3GshJwJQkchN+XWfD3VWBzmaZZTxQgjExjGReF5JJ
+I1xsW+ZUbROqFsPPSjN2iLnRgsSS0et3xWmDewI+VDy+npPloJD6+9wcx/o0yN1
dFlIRqk+Ee4K/Gdfe2pfiy7ngBgZlNSZJGvzooBrn4Y3u6BFt7Xc8Q==
-----END RSA PRIVATE KEY-----
`

	PublicKeyRS256String = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuhIZN1pb0S/0PvCZvzW3
fBS+/5Elg1ACt8pnLOQnye/dKssHGRxihg+hjoVXbahPk2cM/rvoXu0SWtc864g4
Jcu7UoyQdj0SucaLuwMxhJW00d/2MYBqy9l1Vbqiveo+f4H+WwxVpKhpOj5UD1id
axZfgLsGLd1Kk7qYkT5wOBxvC8mfahZJaYXWr/taMH0sWYrJ9rCy9g54fG4LENq8
raLr/vMOkVFtJIR4cuPgd9uL0kPtEKVsQOK1WpaBpZXZiS3f18bkMXVksnhlFv5W
Eta8DoI1F3KMUo+Lz/M4FNS2PWnURoutTy9REO7VDJj9Sge/Ep4CuIWsBoTp9361
oQIDAQAB
-----END PUBLIC KEY-----
`

	KeySet = `{
    "keys": [
		{
			"kty": "RSA",
			"n": "uhIZN1pb0S_0PvCZvzW3fBS-_5Elg1ACt8pnLOQnye_dKssHGRxihg-hjoVXbahPk2cM_rvoXu0SWtc864g4Jcu7UoyQdj0SucaLuwMxhJW00d_2MYBqy9l1Vbqiveo-f4H-WwxVpKhpOj5UD1idaxZfgLsGLd1Kk7qYkT5wOBxvC8mfahZJaYXWr_taMH0sWYrJ9rCy9g54fG4LENq8raLr_vMOkVFtJIR4cuPgd9uL0kPtEKVsQOK1WpaBpZXZiS3f18bkMXVksnhlFv5WEta8DoI1F3KMUo-Lz_M4FNS2PWnURoutTy9REO7VDJj9Sge_Ep4CuIWsBoTp9361oQ",
			"e": "AQAB",
            "alg": "RS256",
            "kid": "1",
            "use": "sig"
        },
		{
			"kty": "RSA",
			"n": "uhIZN1pb0S_0PvCZvzW3fBS-_5Elg1ACt8pnLOQnye_dKssHGRxihg-hjoVXbahPk2cM_rvoXu0SWtc864g4Jcu7UoyQdj0SucaLuwMxhJW00d_2MYBqy9l1Vbqiveo-f4H-WwxVpKhpOj5UD1idaxZfgLsGLd1Kk7qYkT5wOBxvC8mfahZJaYXWr_taMH0sWYrJ9rCy9g54fG4LENq8raLr_vMOkVFtJIR4cuPgd9uL0kPtEKVsQOK1WpaBpZXZiS3f18bkMXVksnhlFv5WEta8DoI1F3KMUo-Lz_M4FNS2PWnURoutTy9REO7VDJj9Sge_Ep4CuIWsBoTp9361oQ",
			"e": "AQAB",
            "alg": "RS256",
            "kid": "2",
            "use": "sig"
        }
    ]
}`
)

func init() {
	TokenAuthHS256 = jwtauth.New(jwa.HS256().String(), TokenSecret, nil, jwt.WithAcceptableSkew(30*time.Second))
}

//
// Tests
//

func TestNewKeySet(t *testing.T) {
	_, err := jwtauth.NewKeySet([]byte("not a valid key set"))
	if err == nil {
		t.Fatal("The error should not be nil")
	}

	_, err = jwtauth.NewKeySet([]byte(KeySet))
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeySetRSA(t *testing.T) {
	privateKeyBlock, _ := pem.Decode([]byte(PrivateKeyRS256String))

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)

	if err != nil {
		t.Fatal(err)
	}

	KeySetAuth, _ := jwtauth.NewKeySet([]byte(KeySet))
	claims := map[string]interface{}{
		"key":  "val",
		"key2": "val2",
		"key3": "val3",
	}

	signed := newJwtRSAToken(jwa.RS256(), privateKey, "1", claims)

	token, err := KeySetAuth.Decode(signed)

	if err != nil {
		t.Fatalf("Failed to decode token string %s\n", err.Error())
	}

	tokenClaims, err := claimsFromToken(token)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !reflect.DeepEqual(claims, tokenClaims) {
		t.Fatalf("The decoded claims don't match the original ones\n")
	}

	_, _, err = KeySetAuth.Encode(claims)
	if err.Error() != "encode not supported" {
		t.Fatalf("Expect error to equal %s. Found: %s.", "encode not supported", err.Error())
	}
}

func TestSimple(t *testing.T) {
	r := chi.NewRouter()

	r.Use(
		jwtauth.Verifier(TokenAuthHS256),
		jwtauth.Authenticator(TokenAuthHS256),
	)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// sending unauthorized requests
	if status, resp := testRequest(t, ts, "GET", "/", nil, nil); status != 401 || resp != "no token found\n" {
		t.Fatal(resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	h.Set("Authorization", "BEARER asdf")
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	// wrong token secret and wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	// correct token secret but wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token(TokenSecret, map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}

	// correct token, but has expired within the skew time
	h.Set("Authorization", "BEARER "+newJwtToken(TokenSecret, map[string]interface{}{"exp": time.Now().Unix() - 29}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 200 || resp != "welcome" {
		fmt.Println("status", status, "resp", resp)
		t.Fatal(resp)
	}

	// correct token, but has expired outside of the skew time
	h.Set("Authorization", "BEARER "+newJwtToken(TokenSecret, map[string]interface{}{"exp": time.Now().Unix() - 31}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 || resp != "token is expired\n" {
		t.Fatal(resp)
	}

	// sending authorized requests
	if status, resp := testRequest(t, ts, "GET", "/", newAuthHeader(), nil); status != 200 || resp != "welcome" {
		t.Fatal(resp)
	}
}

func TestSimpleRSA(t *testing.T) {
	privateKeyBlock, _ := pem.Decode([]byte(PrivateKeyRS256String))

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKeyBlock, _ := pem.Decode([]byte(PublicKeyRS256String))

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	TokenAuthRS256 = jwtauth.New(jwa.RS256().String(), privateKey, publicKey)

	claims := map[string]interface{}{
		"key":  "val",
		"key2": "val2",
		"key3": "val3",
	}

	_, tokenString, err := TokenAuthRS256.Encode(claims)
	if err != nil {
		t.Fatalf("Failed to encode claims %s\n", err.Error())
	}

	token, err := TokenAuthRS256.Decode(tokenString)
	if err != nil {
		t.Fatalf("Failed to decode token string %s\n", err.Error())
	}

	tokenClaims, err := claimsFromToken(token)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !reflect.DeepEqual(claims, tokenClaims) {
		t.Fatalf("The decoded claims don't match the original ones\n")
	}
}

func TestSimpleRSAVerifyOnly(t *testing.T) {
	claims := map[string]interface{}{
		"key":  "val",
		"key2": "val2",
		"key3": "val3",
	}

	privateKeyBlock, _ := pem.Decode([]byte(PrivateKeyRS256String))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tokenString := newJwtRSAToken(jwa.RS256(), privateKey, "", claims)

	publicKeyBlock, _ := pem.Decode([]byte(PublicKeyRS256String))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	TokenAuthRS256 = jwtauth.New(jwa.RS256().String(), nil, publicKey)

	_, _, err = TokenAuthRS256.Encode(claims)
	if err == nil {
		t.Fatalf("Expecting error when encoding claims without signing key")
	}

	token, err := TokenAuthRS256.Decode(tokenString)
	if err != nil {
		t.Fatalf("Failed to decode token string %s\n", err.Error())
	}

	tokenClaims, err := claimsFromToken(token)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(claims, tokenClaims) {
		t.Fatalf("The decoded claims don't match the original ones\n")
	}
}

func TestMore(t *testing.T) {
	r := chi.NewRouter()

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(TokenAuthHS256))

		authenticator := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, _, err := jwtauth.FromContext(r.Context())

				if err != nil {
					http.Error(w, jwtauth.ErrorReason(err).Error(), http.StatusUnauthorized)
					return
				}

				if err := jwt.Validate(token); err != nil {
					http.Error(w, jwtauth.ErrorReason(err).Error(), http.StatusUnauthorized)
					return
				}

				// Token is authenticated, pass it through
				next.ServeHTTP(w, r)
			})
		}
		r.Use(authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())

			if err != nil {
				w.Write([]byte(fmt.Sprintf("error! %v", err)))
				return
			}

			w.Write([]byte(fmt.Sprintf("protected, user:%v", claims["user_id"])))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome"))
		})
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// sending unauthorized requests
	if status, resp := testRequest(t, ts, "GET", "/admin", nil, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	h.Set("Authorization", "BEARER asdf")
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	// wrong token secret and wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	// correct token secret but wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token(TokenSecret, map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}

	h = newAuthHeader(map[string]interface{}{"exp": jwtauth.EpochNow() - 1000})
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is expired\n" {
		t.Fatal(resp)
	}

	// sending authorized requests
	if status, resp := testRequest(t, ts, "GET", "/", nil, nil); status != 200 || resp != "welcome" {
		t.Fatal(resp)
	}

	h = newAuthHeader((map[string]interface{}{"user_id": 31337, "exp": jwtauth.ExpireIn(5 * time.Minute)}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 200 || resp != "protected, user:31337" {
		t.Fatal(resp)
	}
}

func TestKeySet(t *testing.T) {
	privateKeyBlock, _ := pem.Decode([]byte(PrivateKeyRS256String))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()

	keySet, err := jwtauth.NewKeySet([]byte(KeySet))
	if err != nil {
		t.Fatal(err)
	}

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(keySet))

		authenticator := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, _, err := jwtauth.FromContext(r.Context())

				if err != nil {
					http.Error(w, jwtauth.ErrorReason(err).Error(), http.StatusUnauthorized)
					return
				}

				if err := jwt.Validate(token); err != nil {
					http.Error(w, jwtauth.ErrorReason(err).Error(), http.StatusUnauthorized)
					return
				}

				// Token is authenticated, pass it through
				next.ServeHTTP(w, r)
			})
		}
		r.Use(authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())

			if err != nil {
				w.Write([]byte(fmt.Sprintf("error! %v", err)))
				return
			}

			w.Write([]byte(fmt.Sprintf("protected, user:%v", claims["user_id"])))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome"))
		})
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtRSAToken(jwa.RS256(), privateKey, "1", map[string]interface{}{"user_id": 31337, "exp": jwtauth.ExpireIn(5 * time.Minute)}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 200 || resp != "protected, user:31337" {
		t.Fatal(resp)
	}
}

//
// Test helper functions
//

func testRequest(t *testing.T, ts *httptest.Server, method, path string, header http.Header, body io.Reader) (int, string) {
	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	for k, v := range header {
		req.Header.Set(k, v[0])
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}
	defer resp.Body.Close()

	return resp.StatusCode, string(respBody)
}

func newJwtToken(secret []byte, claims ...map[string]interface{}) string {
	token := jwt.New()
	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Set(k, v)
		}
	}

	tokenPayload, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
	if err != nil {
		log.Fatal(err)
	}
	return string(tokenPayload)
}

func newJwt512Token(secret []byte, claims ...map[string]interface{}) string {
	// use-case: when token is signed with a different alg than expected
	token := jwt.New()
	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Set(k, v)
		}
	}
	tokenPayload, err := jwt.Sign(token, jwt.WithKey(jwa.HS512(), secret))
	if err != nil {
		log.Fatal(err)
	}
	return string(tokenPayload)
}

func newJwtRSAToken(alg jwa.SignatureAlgorithm, secret interface{}, kid string, claims ...map[string]interface{}) string {
	token := jwt.New()
	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Set(k, v)
		}
	}

	headers := jws.NewHeaders()
	if kid != "" {
		err := headers.Set("kid", kid)
		if err != nil {
			log.Fatal(err)
		}
	}

	tokenPayload, err := jwt.Sign(token, jwt.WithKey(alg, secret, jws.WithProtectedHeaders(headers)))
	if err != nil {
		log.Fatal(err)
	}
	return string(tokenPayload)
}

func claimsFromToken(token jwt.Token) (map[string]interface{}, error) {
	keys := token.Keys()
	claims := make(map[string]interface{}, len(keys))
	for _, key := range keys {
		var value interface{}
		if err := token.Get(key, &value); err != nil {
			return nil, err
		}
		claims[key] = value
	}
	return claims, nil
}

func newAuthHeader(claims ...map[string]interface{}) http.Header {
	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken(TokenSecret, claims...))
	return h
}
