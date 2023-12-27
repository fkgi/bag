package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fkgi/bag"
)

var (
	nafAuth bag.WWWAuthenticate
	btid    string
	cipher  uint32 = 2
)

func errorResult(w http.ResponseWriter, code int, e error) {
	fmt.Println()
	fmt.Fprintln(os.Stderr, "[ERR]", "NAF procedure failed:", e)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	fmt.Fprint(w, e)
}

func gbaClientHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println()
	fmt.Println("[INFO]", "new HTTP request:", r.Method, r.RequestURI)

	nc := uint64(0)
	reqbody, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	for i := 0; i < authRetransmit; i++ {
		url := naf + r.URL.Path
		req, _ := http.NewRequest(r.Method, url, bytes.NewReader(reqbody))
		req.Header = bag.CloneHeader(r.Header)

		if btid != "" && nafAuth.Nonce != "" {
			nc++
			auth := bag.Authorization{
				Username: btid,
				Realm:    nafAuth.Realm,
				Uri:      req.URL.Path,
				Nonce:    nafAuth.Nonce,
				Nc:       nc,
				Cnonce:   bag.NewRandText(),
				Opaque:   nafAuth.Opaque}
			if auth.Uri == "" {
				auth.Uri = "/"
			}
			auth.Qop = "auth"
			for _, v := range nafAuth.Qop {
				if v == "auth-int" {
					auth.Qop = "auth-int"
				}
			}

			ksnaf := base64.StdEncoding.EncodeToString(bag.KeyDerivation(
				av.CK, av.IK, av.RAND, impi, r.Host, 1, cipher))
			auth.SetResponse(req.Method, []byte(ksnaf), reqbody)
			req.Header.Set("Authorization", auth.String())
		}
		req.Header.Set("User-Agent", uaPrefix+"3gpp-gba")
		if impu != "" {
			req.Header.Set("X-3GPP-Intended-Identity", impu)
		}

		fmt.Println()
		fmt.Println("[INFO]", "transfer request to NAF", req.Host)
		fmt.Println("  >", req.Method, req.URL, req.Proto)
		fmt.Println("  >", "Host :", req.Host)
		for k, v := range req.Header {
			fmt.Println("  >", k, ":", strings.Join(v, ", "))
		}
		if len(reqbody) != 0 {
			fmt.Println()
			fmt.Println("  >", string(reqbody))
		}

		res, e := client.Do(req)
		if e != nil {
			errorResult(w, http.StatusBadGateway,
				fmt.Errorf("failed to access NAF: %s", e))
			return
		}
		fmt.Println()
		fmt.Println("[INFO]", "response from NAF", req.Host)
		if res.TLS == nil {
			fmt.Println("[INFO]", "connection is not TLS")
		} else {
			fmt.Println("[INFO]", "connection is TLS with cipher",
				tls.CipherSuiteName(res.TLS.CipherSuite))
			cipher = 0x0100 | uint32(res.TLS.CipherSuite)
		}
		fmt.Println("  <", res.Proto, res.Status)
		for k, v := range res.Header {
			fmt.Println("  <", k, ":", strings.Join(v, ", "))
		}

		if res.StatusCode != http.StatusUnauthorized {
			authInfo, e := bag.ParseaAuthenticationInfo(
				res.Header.Get("Authentication-Info"))
			if e == nil {
				nafAuth.Nonce = authInfo.Nextnonce
			} else {
				fmt.Println()
				fmt.Fprintln(os.Stderr, "[ERR]",
					"NAF returns invalid Authentication-Info header:", e)
			}

			resbody, e := io.ReadAll(res.Body)
			if e != nil {
				fmt.Println("[ERR]", e)
			}
			defer res.Body.Close()
			if len(resbody) != 0 {
				fmt.Println("  <")
				fmt.Println("  <", string(resbody))
				w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
			}
			w.WriteHeader(res.StatusCode)
			w.Write(resbody)
			return
		}

		fmt.Println()
		fmt.Println("[INFO]", "BSF authentication is required")
		nafAuth, e = bag.ParseaWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
		if e != nil {
			errorResult(w, http.StatusBadGateway,
				fmt.Errorf("invalid WWW-Authenticate header from NAF: %s", e))
			return
		}

		btid, e = bootstrap()
		if e != nil {
			errorResult(w, http.StatusForbidden,
				fmt.Errorf("bootstrap to BFS failed: %s", e))
			return
		}
		fmt.Println()
		fmt.Println("[INFO]", "BSF authentication success, retrying NAF access")
	}

	errorResult(w, http.StatusForbidden,
		errors.New("NAF authentication retry count exceeded"))
}
