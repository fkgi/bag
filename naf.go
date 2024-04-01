package bag

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
)

func ApplicationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", productName+" NAF")

	auth, e := ParseaAuthorization(r.Header.Get("Authorization"))
	if e != nil || auth.Realm == "" {
		w.Header().Set("WWW-Authenticate", WWWAuthenticate{
			Algorithm: "MD5",
			Realm:     "3GPP-bootstrapping@" + r.Host,
			Nonce:     NewRandText(),
			Qop:       qop,
			Opaque:    NewRandText()}.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	av, ttl, e := getCachedAV(auth.Username)
	if ttl.IsZero() {
		w.Header().Set("WWW-Authenticate", WWWAuthenticate{
			Algorithm: "MD5",
			Realm:     "3GPP-bootstrapping@" + r.Host,
			Nonce:     NewRandText(),
			Qop:       qop,
			Opaque:    NewRandText()}.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if auth.Realm != "3GPP-bootstrapping@"+r.Host {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	cres := auth.Response
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	cipher := uint32(2)
	if r.TLS != nil {
		cipher = 0x0100 | uint32(r.TLS.CipherSuite)
	}
	/*
		fmt.Printf("  CK       = %x\n", av.CK)
		fmt.Printf("  IK       = %x\n", av.IK)
		fmt.Printf("  RAND     = %x\n", av.RAND)
		fmt.Printf("  IMPI     = %s\n", av.IMPI)
		fmt.Printf("  NAF host = %s\n", r.Host)
		fmt.Printf("  vendor   = 1\n")
		fmt.Printf("  protocol = %x\n", cipher)
	*/
	ksnaf := base64.StdEncoding.EncodeToString(KeyDerivation(
		av.CK, av.IK, av.RAND, av.IMPI, r.Host, 1, cipher))
	auth.SetResponse(r.Method, []byte(ksnaf), body)
	if auth.Response != cres {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body = []byte("result")
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
