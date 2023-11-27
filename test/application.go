package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/fkgi/bag"
)

var (
	nafAuth   bag.WWWAuthenticate
	nafClient *http.Client
	btid      string
)

func errorResult(w http.ResponseWriter, code int, e error) {
	log.Println(e)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	fmt.Fprint(w, e)
}

func gbaClientHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("new HTTP request:", r.Method, r.RequestURI)

	if nafClient == nil {
		proxy, e := url.Parse(nafurl)
		if e != nil {
			errorResult(w, http.StatusInternalServerError,
				errors.Join(errors.New("invalid NAF URL"), e))
			return
		}

		t := http.DefaultTransport.(*http.Transport)
		t = t.Clone()
		t.Proxy = http.ProxyURL(proxy)
		nafClient = &http.Client{
			Timeout:   time.Second * expire,
			Transport: t}
	}

	nc := uint64(0)
	reqbody, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	for i := 0; i < authRetransmit; i++ {
		req, _ := http.NewRequest(r.Method, r.RequestURI, bytes.NewReader(reqbody))
		if btid != "" && nafAuth.Nonce != "" {
			log.Println("B-TID and NAF nonce found, adding Authorization header")
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

			naf, _ := url.Parse(nafurl)
			auth.SetResponse(req.Method,
				bag.KeyDerivation(av.CK, av.IK, av.RAND, impi, naf.Host), reqbody)
			req.Header.Set("Authorization", auth.String())
		}
		req.Header.Set("User-Agent", uaPrefix+"3gpp-gba")
		req.Header.Set("Accept", "*/*")
		if impu != "" {
			req.Header.Set("X-3GPP-Intended-Identity", impu)
		}

		log.Println("transfer request to NAF", nafurl)
		res, e := nafClient.Do(req)
		if e != nil {
			errorResult(w, http.StatusBadGateway,
				errors.Join(errors.New("failed to access NAF"), e))
			return
		}

		if res.StatusCode != http.StatusUnauthorized {
			authInfo, e := bag.ParseaAuthenticationInfo(
				res.Header.Get("Authentication-Info"))
			if e == nil {
				nafAuth.Nonce = authInfo.Nextnonce
			} else {
				log.Println("NAF returns invalid Authentication-Info header:", e)
			}

			resbody, _ := io.ReadAll(res.Body)
			defer res.Body.Close()
			if len(resbody) != 0 {
				w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
			}
			w.WriteHeader(res.StatusCode)
			w.Write(resbody)
			return
		}

		log.Println("BSF authentication is required")
		nafAuth, e = bag.ParseaWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
		if e != nil {
			errorResult(w, http.StatusBadGateway,
				errors.Join(errors.New("invalid WWW-Authenticate header from NAF"), e))
			return
		}

		btid, e = bootstrap()
		if e != nil {
			errorResult(w, http.StatusForbidden,
				errors.Join(errors.New("bootstrap to BFS failed"), e))
			return
		}
		log.Println("BSF authentication success")
		log.Println("retrying NAF access")
	}

	errorResult(w, http.StatusForbidden,
		errors.New("NAF authentication retry count expired"))
}
