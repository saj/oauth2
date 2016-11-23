package device

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	clientID         = "client"
	clientSecret     = "secret"
	deviceCode       = "device"
	interval         = time.Duration(1) * time.Second
	scopes           = "scope1 scope2"
	grantType        = "http://oauth.net/grant_type/device/1.0"
	stubAccessToken  = "ya29.AHES6ZSuY8f6WFLswSv0HELP2J4cCvFSj-8GiZM0Pr6cgXU"
	stubRefreshToken = "1/551G1yXUqgkDGnkfFk6ZbjMLMDIMxo3JFc8lY8CAR-Q"
)

var scopesSlice = strings.Split(scopes, " ")

func TestTokenRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.String(), "/token"; got != want {
			t.Errorf("request URL = %q; want %q", got, want)
		}
		if got, want := r.Method, "POST"; got != want {
			t.Errorf("request method = %q; want %q", got, want)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type header = %q; want %q", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed reading request body: %v", err)
		}
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed parsing POST data: %v", err)
		}
		if got, want := vals.Get("client_id"), clientID; got != want {
			t.Errorf("client_id = %q; want %q", got, want)
		}
		if got, want := vals.Get("client_secret"), clientSecret; got != want {
			t.Errorf("client_secret = %q; want %q", got, want)
		}
		if got, want := vals.Get("code"), deviceCode; got != want {
			t.Errorf("code = %q; want %q", got, want)
		}
		if got, want := vals.Get("grant_type"), grantType; got != want {
			t.Errorf("grant_type = %q; want %q", got, want)
		}
		if got, want := vals.Get("scope"), scopes; got != want {
			t.Errorf("scope = %q; want %q", got, want)
		}

		response := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    uint   `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
		}{
			AccessToken:  stubAccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: stubRefreshToken,
		}
		b, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	conf := newConf(ts.URL)

	tk, err := conf.Token(oauth2.NoContext)

	if err != nil {
		t.Error(err)
	}
	if !tk.Valid() {
		t.Fatalf("invalid token; got: %#v", tk)
	}
	if got, want := tk.AccessToken, stubAccessToken; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := strings.ToLower(tk.TokenType), "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
}

func TestRetry(t *testing.T) {
	pending := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := struct {
			Error string `json:"error"`
		}{
			Error: "authorization_pending",
		}
		b, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(b)
	})
	token := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    uint   `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
		}{
			AccessToken:  stubAccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: stubRefreshToken,
		}
		b, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
	hs := newHandlerSequence([]http.Handler{pending, pending, token})
	ts := httptest.NewServer(hs)
	conf := newConf(ts.URL)

	tk, err := conf.Token(oauth2.NoContext)

	if err != nil {
		t.Error(err)
	}
	if !tk.Valid() {
		t.Fatalf("invalid token; got: %#v", tk)
	}
	if got, want := tk.AccessToken, stubAccessToken; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := strings.ToLower(tk.TokenType), "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	if got, want := hs.RequestCount(), uint(3); got != want {
		t.Errorf("request count = %q; want %q", got, want)
	}
	if got, want := hs.RequestTimeDelta(0, 1), interval; fuzzyDurationLessThan(got, want) {
		t.Errorf("poll interval = %q; want at least %q", got.String(), want.String())
	}
	if got, want := hs.RequestTimeDelta(1, 2), interval; fuzzyDurationLessThan(got, want) {
		t.Errorf("poll interval = %q; want at least %q", got.String(), want.String())
	}
}

func TestBackoff(t *testing.T) {
	backoff := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := struct {
			Error string `json:"error"`
		}{
			Error: "slow_down",
		}
		b, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(b)
	})
	token := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    uint   `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
		}{
			AccessToken:  stubAccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: stubRefreshToken,
		}
		b, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
	hs := newHandlerSequence([]http.Handler{backoff, backoff, token})
	ts := httptest.NewServer(hs)
	conf := newConf(ts.URL)

	tk, err := conf.Token(oauth2.NoContext)

	if err != nil {
		t.Error(err)
	}
	if !tk.Valid() {
		t.Fatalf("invalid token; got: %#v", tk)
	}
	if got, want := tk.AccessToken, stubAccessToken; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := strings.ToLower(tk.TokenType), "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	if got, want := hs.RequestCount(), uint(3); got != want {
		t.Errorf("request count = %q; want %q", got, want)
	}
	if d1, d2 := hs.RequestTimeDelta(0, 1), hs.RequestTimeDelta(1, 2); fuzzyDurationLessThan(d2, d1) {
		t.Errorf("subsequent request sent without backoff")
	}
}

func newConf(url string) *Config {
	return &Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		DeviceCode:   deviceCode,
		Expires:      time.Now().Add(time.Duration(60) * time.Second),
		Interval:     interval,
		TokenURL:     url + "/token",
		Scopes:       scopesSlice,
	}
}

// A handlerSequence is a http.Handler that responds to each HTTP request in a
// sequence of requests using a different subordinate http.Handler.  A
// handlerSequence will also record the wallclock time of each request and make
// these wallclock times available for inspection with RequestTime() and
// RequestTimeDelta().
type handlerSequence struct {
	handlers     []http.Handler
	requestTimes []time.Time
	requests     uint
	mtx          sync.Mutex
}

func newHandlerSequence(handlers []http.Handler) *handlerSequence {
	return &handlerSequence{
		handlers:     handlers,
		requestTimes: make([]time.Time, 0, len(handlers)),
	}
}

func (h *handlerSequence) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := time.Now()
	h.mtx.Lock()
	i := h.requests
	h.requests++
	h.mtx.Unlock()

	if i < uint(len(h.handlers)) {
		h.requestTimes = append(h.requestTimes, t)
		h.handlers[i].ServeHTTP(w, r)
	} else {
		http.Error(w, "404 sequence exhausted of all handlers", http.StatusNotFound)
	}
}

func (h *handlerSequence) RequestCount() uint {
	return h.requests
}

func (h *handlerSequence) RequestTime(idx uint) time.Time {
	return h.requestTimes[idx]
}

func (h *handlerSequence) RequestTimeDelta(idx1, idx2 uint) time.Duration {
	t1 := h.RequestTime(idx1)
	t2 := h.RequestTime(idx2)
	return t2.Sub(t1)
}

const comparisonFuzz = 0.1

func fuzzyDurationLessThan(d1, d2 time.Duration) bool {
	n1 := float64(d1.Nanoseconds())
	n2 := float64(d2.Nanoseconds())
	return n1 < (n2 - n2*comparisonFuzz)
}
