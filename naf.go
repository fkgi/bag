package bag

import (
	"encoding/hex"
	"net/http"
)

func ApplicationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", productName+" NAF")

	auth, e := ParseaAuthorization(r.Header.Get("Authorization"))
	if e != nil || auth.Username == "" || auth.Realm == "" {
		w.Header().Set("WWW-Authenticate", WWWAuthenticate{
			Algorithm: "MD5",
			Realm:     "3GPP-bootstrapping@" + r.Host,
			Nonce:     NewRandText(),
			Qop:       qop,
			Opaque:    NewRandText()}.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body := []byte("result")
	ks := []byte{0x00, 0x01}
	auth.SetResponse("", []byte(hex.EncodeToString(ks)), body)

	w.Header().Set("Authentication-Info", AuthenticationInfo{
		Nextnonce: NewRandText(),
		Qop:       auth.Qop,
		Rspauth:   auth.Response,
		Cnonce:    auth.Cnonce,
		Nc:        auth.Nc}.String())
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func CloneHeader(h http.Header) http.Header {
	r := h.Clone()
	for _, h := range hopHeaders {
		hv := r.Get(h)
		if hv == "" {
			continue
		}
		if h == "Te" && hv == "trailers" {
			continue
		}
		r.Del(h)
	}
	return r
}
