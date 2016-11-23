// Package device implements Google's device token flow.
//
// This OAuth 2.0 token flow is suitable for use in scenarios where the user is
// unable to open a user-agent on the client.
//
// Google's implementation of the device token flow is similar to, but distinct
// from, draft-ietf-oauth-device-flow.  This package only supports the former.
//
// The caller is responsible for interacting with the remote device endpoint
// themselves.  This package may be used to interact with the remote token
// endpoint once device and user verification codes have been separately
// obtained.
//
// See https://developers.google.com/identity/protocols/OAuth2ForDevices
package device // import "golang.org/x/oauth2/google/device"

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/internal"
)

type Config struct {
	// ClientID is the client's OAuth 2.0 client_id.
	ClientID string

	// ClientSecret is the client's OAuth 2.0 client_secret.
	ClientSecret string

	// DeviceCode is the device verification code.  Google's documentation
	// refers to this value as the device_code.  DeviceCode is supplied to the
	// token endpoint as an authorization code in exchange for a token.  The
	// remote device endpoint should supply this value.
	DeviceCode string

	// Expires is the time at which the device and user verification codes
	// expire.  After this time, the remote token endpoint will refuse to
	// exchange these codes for tokens.  The remote device endpoint should
	// supply this value together with the verification codes.
	Expires time.Time

	// Interval is the minimum interval at which the remote token endpoint will
	// be polled while we wait for the user to punch in their verification code.
	// The remote device endpoint should supply this value together with the
	// verification codes.
	Interval time.Duration

	// TokenURL is the resource server's token endpoint URL.  This is a constant
	// specific to each server.
	TokenURL string

	// Scopes specifies a set of OAuth 2.0 access token scopes.
	Scopes []string
}

// Token uses a device verification code to retrieve a token.  The device
// verification code will be consumed, and become invalid, upon a successful
// call to this function.
//
// Token will block until the user has punched in their verification code and a
// token has been divulged by the endpoint.  The remote token endpoint will be
// polled at an interval no shorter than c.Interval until a token is divulged or
// c.Expires is reached.
//
// The HTTP client to use is derived from the context.  If nil,
// http.DefaultClient is used.
func (c *Config) Token(ctx context.Context) (*oauth2.Token, error) {
	var tk *oauth2.Token

	expired := time.NewTimer(c.Expires.Sub(time.Now()))
	defer expired.Stop()

	ticker := newBackoffTicker(c.Interval)
	defer ticker.Stop()

PollLoop:
	for {
		select {
		case <-expired.C:
			return nil, fmt.Errorf("verification codes have expired")

		case <-ticker.C():
			var err error
			tk, err = c.poll(ctx)
			if err != nil {
				switch err.(type) {
				case authzPending:
					continue
				case slowDown:
					ticker.BackOff()
					continue
				}
				return nil, err
			}
			break PollLoop
		}
	}
	return tk, nil
}

func (c *Config) poll(ctx context.Context) (*oauth2.Token, error) {
	v := url.Values{
		"code":       {c.DeviceCode},
		"grant_type": {"http://oauth.net/grant_type/device/1.0"},
		"scope":      internal.CondVal(strings.Join(c.Scopes, " ")),
	}
	tk, err := retrieveToken(ctx, c.ClientID, c.ClientSecret, c.TokenURL, v)
	if err != nil {
		return nil, err
	}

	t := &oauth2.Token{
		AccessToken:  tk.AccessToken,
		TokenType:    tk.TokenType,
		RefreshToken: tk.RefreshToken,
		Expiry:       tk.Expiry,
	}
	return t.WithExtra(tk.Raw), nil
}

func retrieveToken(ctx context.Context, clientID, clientSecret, tokenURL string, v url.Values) (*internal.Token, error) {
	hc, err := internal.ContextClient(ctx)
	if err != nil {
		return nil, err
	}
	v.Set("client_id", clientID)
	if clientSecret != "" {
		v.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	var token *internal.Token
	var errmsg string
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		token = &internal.Token{
			AccessToken:  vals.Get("access_token"),
			TokenType:    vals.Get("token_type"),
			RefreshToken: vals.Get("refresh_token"),
			Raw:          vals,
		}
		expires, _ := strconv.Atoi(vals.Get("expires_in"))
		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
		errmsg = vals.Get("error")
	default:
		var tj tokenJSON
		if err = json.Unmarshal(body, &tj); err != nil {
			return nil, err
		}
		token = &internal.Token{
			AccessToken:  tj.AccessToken,
			TokenType:    tj.TokenType,
			RefreshToken: tj.RefreshToken,
			Expiry:       tj.expiry(),
			Raw:          make(map[string]interface{}),
		}
		json.Unmarshal(body, &token.Raw) // no error checks for optional fields
		if v, ok := token.Raw.(map[string]interface{})["error"]; ok {
			errmsg = v.(string)
		}
	}

	if code := r.StatusCode; code < 200 || code > 299 {
		switch errmsg {
		default:
			return nil, fmt.Errorf("oauth2: cannot fetch token: %v", errmsg)
		case "authorization_pending":
			return nil, authzPending(errmsg)
		case "slow_down":
			return nil, slowDown(errmsg)
		case "":
		}
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	// Don't overwrite `RefreshToken` with an empty value
	// if this was a token refreshing request.
	if token.RefreshToken == "" {
		token.RefreshToken = v.Get("refresh_token")
	}
	return token, nil
}

type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"`
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	*e = expirationTime(i)
	return nil
}

type authzPending string

func (e authzPending) Error() string {
	return string(e)
}

type slowDown string

func (e slowDown) Error() string {
	return string(e)
}
