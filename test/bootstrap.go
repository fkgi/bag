package main

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fkgi/bag"
)

var (
	bsfAuth   bag.WWWAuthenticate
	bsfClient *http.Client
)

func bootstrap() (string, error) {
	if bsfClient == nil {
		bsfClient = new(http.Client)
		bsfClient.Timeout = time.Second * expire
	}

	for i := 0; i < authRetransmit; i++ {
		req, _ := http.NewRequest(http.MethodGet, bsfurl, nil)
		auth := bag.Authorization{
			Username: impi,
			Realm:    req.Host,
			Uri:      req.URL.Path}
		if auth.Uri == "" {
			auth.Uri = "/"
		}
		if bsfAuth.Nonce != "" {
			fmt.Println("BSF nonce found, adding Authorization header")
			auth.Nonce = bsfAuth.Nonce
			auth.Cnonce = bag.NewRandText()
			auth.Opaque = bsfAuth.Opaque
			auth.Qop = "auth"
			auth.Nc = 1
			for _, v := range bsfAuth.Qop {
				if v == "auth-int" {
					auth.Qop = "auth-int"
				}
			}
			auth.SetResponse(req.Method, hex.EncodeToString(av.RES), []byte{})
		}
		req.Header.Set("Authorization", auth.String())
		req.Header.Set("User-Agent", uaPrefix+"3gpp-gba")
		req.Header.Set("Accept", "*/*")

		fmt.Println("bootstrapping to", bsfurl)
		fmt.Println(">", req.Method, req.URL, req.Proto)
		fmt.Println(">", "Host :", req.Host)
		for k, v := range req.Header {
			fmt.Println(">", k, ":", strings.Join(v, ", "))
		}
		res, e := bsfClient.Do(req)
		if e != nil {
			e = errors.Join(errors.New("failed to access BSF"), e)
			return "", e
		}
		fmt.Println("<", res.Proto, res.Status)
		for k, v := range res.Header {
			fmt.Println("<", k, ":", strings.Join(v, ", "))
		}

		switch res.StatusCode {
		case http.StatusUnauthorized:
			bsfAuth, e = bag.ParseaWWWAuthenticate(
				res.Header.Get("WWW-Authenticate"))
			if e != nil || bsfAuth.Realm == "" || bsfAuth.Nonce == "" {
				e = errors.Join(errors.New("no valid WWW-Authenticate in BSF challenge"), e)
				return "", e
			}
		case http.StatusOK:
			authInfo, e := bag.ParseaAuthenticationInfo(
				res.Header.Get("Authentication-Info"))
			if e == nil {
				bsfAuth.Nonce = authInfo.Nextnonce
			} else {
				fmt.Println("BSF returns invalid Authentication-Info header:", e)
			}

			data, _ := io.ReadAll(res.Body)
			defer res.Body.Close()
			info := bag.BootstrappingInfo{}
			e = xml.Unmarshal(data, &info)

			return info.BTID, e
		default:
			return "", errors.New("invalid BSF response" + res.Status)
		}
		fmt.Println("retrying BSF access")
	}

	return "", errors.New("bootstraping authentication retry count expired")
}
