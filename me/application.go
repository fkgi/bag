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
	fmt.Fprintln(os.Stderr, "\n", "[ERR]", "NAF procedure failed:", e)
	return common.MeAns{
		Code: code,
		Body: []byte(e.Error()),
	}
}

func gbaClientHandler(r common.MeReq) common.MeAns {
	fmt.Println("\n", "[INFO]", "starting new HTTP request:", r.Method, r.RequestURI)

	query := common.DBQuery{
		IMPI: r.IMPI,
		Ch:   make(chan bag.AV, 1)}
	common.Queue <- query
	av := <-query.Ch
	av.IMPI = r.IMPI

	fmt.Println("\n", "[INFO]", "retrieved AV info")
	fmt.Printf("  | RAND     = %x\n", av.RAND)
	fmt.Printf("  | AUTN     = %x\n", av.AUTN)
	fmt.Printf("  | RES      = %x\n", av.RES)
	fmt.Printf("  | IK       = %x\n", av.IK)
	fmt.Printf("  | CK       = %x\n", av.CK)
	fmt.Printf("  | IMPI     = %s\n", av.IMPI)

	if len(r.RAND) != 0 {
		av.RAND = r.RAND
		fmt.Printf("[INFO] override AV RAND to %x\n", av.RAND)
	}
	if len(r.AUTN) != 0 {
		av.AUTN = r.AUTN
		fmt.Printf("[INFO] override AV AUTN to %x\n", av.AUTN)
	}
	if len(r.RES) != 0 {
		av.RES = r.RES
		fmt.Printf("[INFO] override AV RES to %x\n", av.RES)
	}
	if len(r.IK) != 0 {
		av.IK = r.IK
		fmt.Printf("[INFO] override AV IK to %x\n", av.IK)
	}
	if len(r.CK) != 0 {
		av.CK = r.CK
		fmt.Printf("[INFO] override AV CK to %x\n", av.CK)
	}

	if r.ClearCache {
		fmt.Println("[INFO]", "cache of Authenticate and B-TID is cleared")
		delete(nafAuthMap, r.IMPI)
		delete(btidMap, r.IMPI)
	}

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
			fmt.Println("\n", "[INFO]", "Ks_naf", ksnaf, "is generated from")
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

		fmt.Println("\n", "[INFO]", "transfer request to NAF", req.Host)
		fmt.Println("  >", req.Method, req.URL, req.Proto)
		fmt.Println("  >", "Host :", req.Host)
		logHeader(req.Header, "  >")

		if len(r.Body) != 0 {
			fmt.Println("\n", "  >", string(r.Body))
		}

		res, e := client.Do(req)
		if e != nil {
			return errorResult(http.StatusBadGateway,
				fmt.Errorf("failed to access NAF: %s", e))
		}
		fmt.Println("\n", "[INFO]", "response from NAF", req.Host)
		if res.TLS == nil {
			fmt.Println("[INFO]", "connection is not TLS")
		} else {
			fmt.Println("[INFO]", "connection is TLS with cipher",
				tls.CipherSuiteName(res.TLS.CipherSuite))
			cipher = 0x0100 | uint32(res.TLS.CipherSuite)
		}
		fmt.Println("  <", res.Proto, res.Status)
		logHeader(res.Header, "  <")

		if res.StatusCode != http.StatusUnauthorized {
			authInfo, e := bag.ParseaAuthenticationInfo(
				res.Header.Get("Authentication-Info"))
			if e == nil {
				nafAuth.Nonce = authInfo.Nextnonce
				nafAuthMap[r.IMPI] = nafAuth
			} else {
				fmt.Fprintln(os.Stderr, "\n", "[ERR]",
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
		fmt.Println("\n", "[INFO]", "NAF Authenticate data is cached, entry =", len(nafAuthMap))

		fmt.Println("\n", "[INFO]", "BSF authentication is required")
		btid, e = bootstrap(av)
		if e != nil {
			return errorResult(http.StatusForbidden,
				fmt.Errorf("bootstrap to BFS failed: %s", e))
		}
		btidMap[r.IMPI] = btid
		fmt.Println("\n", "[INFO]", "B-TID is cached, entry =", len(btidMap))

		fmt.Println("\n", "[INFO]", "BSF authentication success, retrying NAF access")
	}

	return errorResult(http.StatusForbidden,
		errors.New("NAF authentication retry count exceeded"))
}