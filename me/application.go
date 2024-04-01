package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/fkgi/bag"
	"github.com/fkgi/bag/common"
)

var (
	nafAuthMap = map[string]bag.WWWAuthenticate{}
	btidMap    = map[string]string{}
)

func gbaClientSession(c net.Conn) {
	defer c.Close()

	dec := gob.NewDecoder(c)
	enc := gob.NewEncoder(c)

	for {
		r := common.MeReq{}
		e := dec.Decode(&r)
		if e == io.EOF {
			break
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, "[ERR]", "GOB request encoding failed:", e)
			break
		}

		e = enc.Encode(gbaClientHandler(r))
		if e != nil {
			fmt.Fprintln(os.Stderr, "[ERR]", "GOB answer decoding failed:", e)
			return
		}
	}
}

func errorResult(code int, e error) common.MeAns {
	fmt.Println()
	fmt.Fprintln(os.Stderr, "[ERR]", "NAF procedure failed:", e)
	return common.MeAns{
		Code: code,
		Body: []byte(e.Error()),
	}
}

func gbaClientHandler(r common.MeReq) common.MeAns {
	fmt.Println()
	fmt.Println("[INFO]", "starting new HTTP request:", r.Method, r.RequestURI)

	dbr := common.DbReq{IMPI: r.IMPI}
	e := enc.Encode(dbr)
	if e != nil {
		fmt.Fprintln(os.Stderr, "[ERR]", "faild to encode DB request:", e)
		return errorResult(http.StatusInternalServerError, e)
	}
	av := bag.AV{}
	e = dec.Decode(&av)
	if e != nil {
		fmt.Fprintln(os.Stderr, "[ERR]", "faild to decode DB answer:", e)
		return errorResult(http.StatusInternalServerError, e)
	}
	fmt.Println()
	fmt.Println("[INFO]", "retrieved AV info")
	fmt.Printf("  | RAND     = %x\n", av.RAND)
	fmt.Printf("  | AUTN     = %x\n", av.AUTN)
	fmt.Printf("  | RES      = %x\n", av.RES)
	fmt.Printf("  | IK       = %x\n", av.IK)
	fmt.Printf("  | CK       = %x\n", av.CK)
	fmt.Printf("  | IMPI     = %s\n", av.IMPI)

	var nc uint64 = 0
	var cipher uint32 = 2

	for i := 0; i < authRetransmit; i++ {
		nafAuth := nafAuthMap[r.IMPI]
		btid := btidMap[r.IMPI]

		req, _ := http.NewRequest(r.Method, r.RequestURI, bytes.NewReader(r.Body))

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
				av.CK, av.IK, av.RAND, av.IMPI, req.Host, 1, cipher))
			fmt.Println("[INFO]", "Ks_naf", ksnaf, "is generated from")
			fmt.Printf("  | CK       = %x\n", av.CK)
			fmt.Printf("  | IK       = %x\n", av.IK)
			fmt.Printf("  | RAND     = %x\n", av.RAND)
			fmt.Printf("  | IMPI     = %s\n", av.IMPI)
			fmt.Printf("  | NAF host = %s\n", req.Host)
			fmt.Printf("  | vendor   = 1\n")
			fmt.Printf("  | protocol = %x\n", cipher)

			auth.SetResponse(req.Method, []byte(ksnaf), r.Body)
			req.Header.Set("Authorization", auth.String())
		}
		req.Header.Set("User-Agent", uaPrefix+"3gpp-gba")
		if r.IMPU != "" {
			req.Header.Set("X-3GPP-Intended-Identity", r.IMPU)
		}

		fmt.Println()
		fmt.Println("[INFO]", "transfer request to NAF", req.Host)
		fmt.Println("  >", req.Method, req.URL, req.Proto)
		fmt.Println("  >", "Host :", req.Host)
		for k, v := range req.Header {
			fmt.Println("  >", k, ":", strings.Join(v, ", "))
		}
		if len(r.Body) != 0 {
			fmt.Println()
			fmt.Println("  >", string(r.Body))
		}

		res, e := client.Do(req)
		if e != nil {
			return errorResult(http.StatusBadGateway,
				fmt.Errorf("failed to access NAF: %s", e))
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
				nafAuthMap[r.IMPI] = nafAuth
			} else {
				fmt.Println()
				fmt.Fprintln(os.Stderr, "[ERR]",
					"NAF returns invalid Authentication-Info header:", e)
			}

			ans := common.MeAns{
				Code: res.StatusCode,
			}
			ans.Body, e = io.ReadAll(res.Body)
			if e != nil {
				fmt.Println("[ERR]", e)
			}
			defer res.Body.Close()
			if len(ans.Body) != 0 {
				fmt.Println("  <")
				fmt.Println("  <", string(ans.Body))
			}
			return ans
		}

		nafAuth, e = bag.ParseaWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
		if e != nil {
			return errorResult(http.StatusBadGateway,
				fmt.Errorf("invalid WWW-Authenticate header from NAF: %s", e))
		}
		nafAuthMap[r.IMPI] = nafAuth
		fmt.Println()
		fmt.Println("[INFO]", "NAF Authenticate data is cached, entry =", len(nafAuthMap))

		fmt.Println()
		fmt.Println("[INFO]", "BSF authentication is required")
		btid, e = bootstrap(av)
		if e != nil {
			return errorResult(http.StatusForbidden,
				fmt.Errorf("bootstrap to BFS failed: %s", e))
		}
		btidMap[r.IMPI] = btid
		fmt.Println()
		fmt.Println("[INFO]", "B-TID is cached, entry =", len(btidMap))

		fmt.Println()
		fmt.Println("[INFO]", "BSF authentication success, retrying NAF access")
	}

	return errorResult(http.StatusForbidden,
		errors.New("NAF authentication retry count exceeded"))
}
