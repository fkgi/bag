package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fkgi/bag"
)

func bootstrap(av bag.AV, client *http.Client) (string, error) {
	bsfAuth := bag.WWWAuthenticate{}

	for i := 0; i < authRetransmit; i++ {
		req, _ := http.NewRequest(http.MethodGet, bsf, nil)
		auth := bag.Authorization{
			Username: av.IMPI,
			Realm:    req.Host,
			Uri:      req.URL.Path}
		if auth.Uri == "" {
			auth.Uri = "/"
		}
		if bsfAuth.Nonce != "" {
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

			d, _ := base64.StdEncoding.DecodeString(bsfAuth.Nonce)
			if bytes.Equal(d[16:], av.AUTN) {
				auth.SetResponse(req.Method, av.RES, []byte{})
			} else {
				// registerAV()
				auth.SetResponse(req.Method, []byte{}, []byte{})
				auth.Auts = base64.StdEncoding.EncodeToString(
					append(av.AUTN[:6], av.AUTN[8:]...))
			}
		}
		req.Header.Set("Authorization", auth.String())
		req.Header.Set("User-Agent", uaPrefix+"3gpp-gba")
		req.Header.Set("Accept", "*/*")

		if *verbose {
			fmt.Println("\n", "[INFO]", "bootstrapping to", req.Host)
			fmt.Println("  >", req.Method, req.URL, req.Proto)
			fmt.Println("  >", "Host :", req.Host)
			logHeader(req.Header, "  >")
		}

		res, e := client.Do(req)
		if e != nil {
			return "", fmt.Errorf("failed to access BSF: %s", e)
		}
		if *verbose {
			fmt.Println("\n", "[INFO]", "response from BSF", req.Host)

			if res.TLS == nil {
				fmt.Println("", "[INFO]", "connection is not TLS")
			} else {
				fmt.Println("", "[INFO]", "connection is TLS with cipher",
					tls.CipherSuiteName(res.TLS.CipherSuite))
			}
			fmt.Println("  <", res.Proto, res.Status)
			logHeader(res.Header, "  <")
		}

		switch res.StatusCode {
		case http.StatusUnauthorized:
			bsfAuth, e = bag.ParseaWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
			if e != nil || bsfAuth.Realm == "" || bsfAuth.Nonce == "" {
				return "", fmt.Errorf("no valid WWW-Authenticate header in BSF challenge: %s", e)
			}
			d, e := base64.StdEncoding.DecodeString(bsfAuth.Nonce)
			if e != nil {
				return "", fmt.Errorf("invalid nonce in WWW-Authenticate in BSF challenge: %s", e)
			}
			if len(d) != 32 {
				return "", errors.New("invalid nonce in WWW-Authenticate in BSF challenge: " +
					"data size is not 16+16 octets")
			}

			if *verbose {
				fmt.Println("\n", "[INFO]", "AKA authentication is required")
				fmt.Printf("  | RAND = %x\n", d[:16])
				fmt.Printf("  | AUTN = %x\n", d[16:])
			}
		case http.StatusOK:
			/*
				authInfo, e := bag.ParseaAuthenticationInfo(
					res.Header.Get("Authentication-Info"))
				if e == nil {
					bsfAuth.Nonce = authInfo.Nextnonce
				} else {
					fmt.Println("BSF returns invalid Authentication-Info header:", e)
				}
			*/

			data, _ := io.ReadAll(res.Body)
			defer res.Body.Close()
			if len(data) != 0 && *verbose {
				fmt.Println("  <")
				fmt.Println("  <", string(data))
			}
			info := struct {
				Xmlns   string `xml:"xmlns,attr"`
				BTID    string `xml:"btid"`
				Liftime string `xml:"lifetime"`
			}{}
			e = xml.Unmarshal(data, &info)

			return info.BTID, e
		default:
			return "", errors.New("unexpected BSF response " + res.Status)
		}
		if *verbose {
			fmt.Println("\n", "[INFO]", "retrying BSF access")
		}
	}

	return "", errors.New("bootstraping authentication retry count exceeded")
}

func logHeader(h http.Header, prefix string) {
	for k, v := range h {
		lk := strings.ToLower(k)
		if lk == "www-authenticate" || lk == "authorization" || lk == "authentication-info" {
			s := strings.TrimSpace(v[0])
			ss := strings.SplitN(strings.TrimSpace(s), " ", 2)

			buf := new(bytes.Buffer)
			buf.WriteString(prefix)
			buf.WriteRune(' ')
			buf.WriteString(k)
			buf.WriteString(" : ")
			buf.WriteString(ss[0])
			buf.WriteRune('\n')

			for _, s = range strings.Split(strings.TrimSpace(ss[1]), ",") {
				buf.WriteString(prefix)
				buf.WriteString("   ")
				buf.WriteString(strings.TrimSpace(s))
				buf.WriteRune('\n')
			}
			fmt.Print(buf.String())
		} else {
			fmt.Println(prefix, k, ":", strings.Join(v, ", "))
		}
	}
}
