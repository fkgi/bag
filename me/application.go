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
	"net/url"
	"os"

	"github.com/fkgi/bag"
	"github.com/fkgi/bag/common"
)

type clientInfo struct {
	auth   bag.WWWAuthenticate
	btid   string
	client *http.Client
	cipher uint32
}

var clientMap = make(chan (map[string]clientInfo), 1)

func init() {
	clientMap <- map[string]clientInfo{}
}

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
			fmt.Fprintln(os.Stderr, "", "[ERR]", "ctrl RPC request decode failed:", e)
			break
		}

		e = enc.Encode(gbaClientHandler(r))
		if e != nil {
			fmt.Fprintln(os.Stderr, "", "[ERR]", "ctrl RPC answer encode failed:", e)
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
	if *verbose {
		fmt.Println("\n", "[INFO]", "starting new GBA request:", r.Method, r.RequestURI)
	}

	av := common.QueryDB(r.IMPI)
	av.IMPI = r.IMPI

	if *verbose {
		fmt.Println("\n", "[INFO]", "retrieved AV info")
		fmt.Printf("  | RAND     = %x\n", av.RAND)
		fmt.Printf("  | AUTN     = %x\n", av.AUTN)
		fmt.Printf("  | RES      = %x\n", av.RES)
		fmt.Printf("  | IK       = %x\n", av.IK)
		fmt.Printf("  | CK       = %x\n", av.CK)
		fmt.Printf("  | IMPI     = %s\n", av.IMPI)
	}

	if len(r.RAND) != 0 {
		av.RAND = r.RAND
		if *verbose {
			fmt.Printf(" [INFO] override AV RAND to %x\n", av.RAND)
		}
	}
	if len(r.AUTN) != 0 {
		av.AUTN = r.AUTN
		if *verbose {
			fmt.Printf(" [INFO] override AV AUTN to %x\n", av.AUTN)
		}
	}
	if len(r.RES) != 0 {
		av.RES = r.RES
		if *verbose {
			fmt.Printf(" [INFO] override AV RES to %x\n", av.RES)
		}
	}
	if len(r.IK) != 0 {
		av.IK = r.IK
		if *verbose {
			fmt.Printf(" [INFO] override AV IK to %x\n", av.IK)
		}
	}
	if len(r.CK) != 0 {
		av.CK = r.CK
		if *verbose {
			fmt.Printf(" [INFO] override AV CK to %x\n", av.CK)
		}
	}

	u, _ := url.ParseRequestURI(r.RequestURI)
	infoKey := u.Scheme + "://" + u.Host + "/" + r.IMPI

	if r.ClearCache {
		if *verbose {
			fmt.Println(" [INFO]", "cache of Authenticate and B-TID is cleared")
		}
		cm := <-clientMap
		delete(cm, infoKey)
		clientMap <- cm
	}

	cm := <-clientMap
	info, ok := cm[infoKey]
	clientMap <- cm
	if !ok {
		info.client = &http.Client{Timeout: expire, Transport: transport.Clone()}
		info.cipher = 2
	}

	var nc uint64 = 0

	for i := 0; i < authRetransmit; i++ {
		req, _ := http.NewRequest(r.Method, r.RequestURI, bytes.NewReader(r.Body))

		if info.btid != "" && info.auth.Nonce != "" {
			nc++
			auth := bag.Authorization{
				Username: info.btid,
				Realm:    info.auth.Realm,
				Uri:      req.URL.Path,
				Nonce:    info.auth.Nonce,
				Nc:       nc,
				Cnonce:   bag.NewRandText(),
				Opaque:   info.auth.Opaque}
			if auth.Uri == "" {
				auth.Uri = "/"
			}
			auth.Qop = "auth"
			for _, v := range info.auth.Qop {
				if v == "auth-int" {
					auth.Qop = "auth-int"
				}
			}

			ksnaf := base64.StdEncoding.EncodeToString(bag.KeyDerivation(
				av.CK, av.IK, av.RAND, av.IMPI, req.Host, 1, info.cipher))
			if *verbose {
				fmt.Println("\n", "[INFO]", "Ks_naf", ksnaf, "is generated from")
				fmt.Printf("  | CK       = %x\n", av.CK)
				fmt.Printf("  | IK       = %x\n", av.IK)
				fmt.Printf("  | RAND     = %x\n", av.RAND)
				fmt.Printf("  | IMPI     = %s\n", av.IMPI)
				fmt.Printf("  | NAF host = %s\n", req.Host)
				fmt.Printf("  | vendor   = 1\n")
				fmt.Printf("  | protocol = %x\n", info.cipher)
			}

			auth.SetResponse(req.Method, []byte(ksnaf), r.Body)
			req.Header.Set("Authorization", auth.String())
		}
		req.Header.Set("User-Agent", uaPrefix+"3gpp-gba")
		if r.IMPU != "" {
			req.Header.Set("X-3GPP-Intended-Identity", r.IMPU)
		}

		if *verbose {
			fmt.Println("\n", "[INFO]", "transfer request to NAF", req.Host)
			fmt.Println("  >", req.Method, req.URL, req.Proto)
			fmt.Println("  >", "Host :", req.Host)
			logHeader(req.Header, "  >")
			if len(r.Body) != 0 {
				fmt.Println("\n", "  >", string(r.Body))
			}
		}

		res, e := info.client.Do(req)
		if e != nil {
			return errorResult(http.StatusBadGateway,
				fmt.Errorf("failed to access NAF: %s", e))
		}
		if *verbose {
			fmt.Println("\n", "[INFO]", "response from NAF", req.Host)
		}
		if res.TLS == nil {
			if *verbose {
				fmt.Println("", "[INFO]", "connection is not TLS")
			}
		} else {
			if *verbose {
				fmt.Println("", "[INFO]", "connection is TLS with cipher",
					tls.CipherSuiteName(res.TLS.CipherSuite))
			}
			info.cipher = 0x0100 | uint32(res.TLS.CipherSuite)
		}
		if *verbose {
			fmt.Println("  <", res.Proto, res.Status)
			logHeader(res.Header, "  <")
		}

		if res.StatusCode != http.StatusUnauthorized {
			authInfo, e := bag.ParseaAuthenticationInfo(
				res.Header.Get("Authentication-Info"))
			if e == nil {
				info.auth.Nonce = authInfo.Nextnonce
				cm := <-clientMap
				cm[infoKey] = info
				clientMap <- cm
			} else {
				fmt.Fprintln(os.Stderr, "\n", "[ERR]",
					"NAF returns invalid Authentication-Info header:", e)
			}

			ans := common.MeAns{
				Code: res.StatusCode,
			}
			ans.Body, e = io.ReadAll(res.Body)
			if e != nil {
				fmt.Println("", "[ERR]", "read response body failed:", e)
			}
			defer res.Body.Close()
			if len(ans.Body) != 0 && *verbose {
				fmt.Println("  <")
				fmt.Println("  <", string(ans.Body))
			}
			return ans
		}

		info.auth, e = bag.ParseaWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
		if e != nil {
			return errorResult(http.StatusBadGateway,
				fmt.Errorf("invalid WWW-Authenticate header from NAF: %s", e))
		}
		if *verbose {
			fmt.Println("\n", "[INFO]", "BSF authentication is required")
		}

		info.btid, e = bootstrap(av, info.client)
		if e != nil {
			return errorResult(http.StatusForbidden,
				fmt.Errorf("bootstrap to BFS failed: %s", e))
		}
		cm := <-clientMap
		cm[infoKey] = info
		clientMap <- cm
		if *verbose {
			fmt.Println("\n", "[INFO]", "NAF Authenticate data and B-TID are cached, entry =", len(cm))
			fmt.Println("\n", "[INFO]", "BSF authentication success, retrying NAF access")
		}
	}

	return errorResult(http.StatusForbidden,
		errors.New("NAF authentication retry count exceeded"))
}
