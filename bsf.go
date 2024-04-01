package bag

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type AV struct {
	RAND []byte // 128 bit AKA RAND
	AUTN []byte // SQN(48)+AMF(16)+MAC(64)=128 bit AKA AUTN
	RES  []byte // 128 bit AKA RES
	IK   []byte // 128 bit AKA IK
	CK   []byte // 128 bit AKA CK
	IMPI string
}

func (a *AV) UnmarshalJSON(b []byte) (e error) {
	var tmp struct {
		RAND string `json:"RAND,omitempty"`
		AUTN string `json:"AUTN,omitempty"`
		RES  string `json:"RES,omitempty"`
		IK   string `json:"IK,omitempty"`
		CK   string `json:"CK,omitempty"`
	}

	if e = json.Unmarshal(b, &tmp); e != nil {
		return
	}
	if a.RAND, e = hex.DecodeString(tmp.RAND); e != nil {
		return
	}
	if a.AUTN, e = hex.DecodeString(tmp.AUTN); e != nil {
		return
	}
	if a.RES, e = hex.DecodeString(tmp.RES); e != nil {
		return
	}
	if a.IK, e = hex.DecodeString(tmp.IK); e != nil {
		return
	}
	a.CK, e = hex.DecodeString(tmp.CK)
	return
}

func (a AV) MarshalJSON() (b []byte, e error) {
	type tmp struct {
		RAND string `json:"RAND,omitempty"`
		AUTN string `json:"AUTN,omitempty"`
		RES  string `json:"RES,omitempty"`
		IK   string `json:"IK,omitempty"`
		CK   string `json:"CK,omitempty"`
	}
	return json.Marshal(tmp{
		RAND: hex.EncodeToString(a.RAND),
		AUTN: hex.EncodeToString(a.AUTN),
		RES:  hex.EncodeToString(a.RES),
		IK:   hex.EncodeToString(a.IK),
		CK:   hex.EncodeToString(a.CK)})
}

func (a *AV) UnmarshalText(b []byte) (e error) {
	s := strings.SplitN(string(b), ":", 6)
	if len(s) != 6 {
		e = fmt.Errorf("invalid data")
	} else if a.RAND, e = hex.DecodeString(s[0]); e != nil || len(a.RAND) != 16 {
		e = fmt.Errorf("invalid data")
	} else if a.AUTN, e = hex.DecodeString(s[1]); e != nil || len(a.AUTN) != 16 {
		e = fmt.Errorf("invalid data")
	} else if a.RES, e = hex.DecodeString(s[2]); e != nil {
		e = fmt.Errorf("invalid data")
	} else if a.IK, e = hex.DecodeString(s[3]); e != nil || len(a.IK) != 16 {
		e = fmt.Errorf("invalid data")
	} else if a.CK, e = hex.DecodeString(s[4]); e != nil || len(a.CK) != 16 {
		e = fmt.Errorf("invalid data")
	} else {
		a.IMPI = s[5]
	}
	return
}

func (a AV) MarshalText() (b []byte, e error) {
	b = []byte(hex.EncodeToString(a.RAND) +
		":" + hex.EncodeToString(a.AUTN) +
		":" + hex.EncodeToString(a.RES) +
		":" + hex.EncodeToString(a.IK) +
		":" + hex.EncodeToString(a.CK) +
		":" + a.IMPI)
	return
}

func (a AV) String() string {
	return fmt.Sprintf(
		"AV for %s, RAND=%x, AUTN=%x, RES=%x, IK=%x, CK=%x",
		a.IMPI, a.RAND, a.AUTN, a.RES, a.IK, a.CK)
}

/*
	func (a AV) MarshalXML(e *xml.Encoder, s xml.StartElement) error {
		tmp := struct {
			Xmlns   string `xml:"xmlns,attr"`
			BTID    string `xml:"btid"`
			Liftime string `xml:"lifetime"`
		}{
			"uri:3gpp-gba",
			base64.StdEncoding.EncodeToString(a.RAND) + "@" + a.Host,
			a.Expires.UTC().Format(time.RFC3339)}
		return e.EncodeElement(tmp, s)
	}
*/

var (
	bsfResultInvalidRequest = http.StatusBadRequest
	bsfResultUnableToGetAV  = http.StatusForbidden
)

func makeBTID(auth Authorization) string {
	tmp := sha256.Sum256([]byte(auth.Nonce + auth.Username))
	return base64.StdEncoding.EncodeToString(tmp[:]) + "@" + auth.Realm
}

func BootstrapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", productName+" BSF")

	auth, e := ParseaAuthorization(r.Header.Get("Authorization"))
	if e != nil {
		w.WriteHeader(bsfResultInvalidRequest)
		return
	}

	if strings.Contains(r.Host, ":") {
		r.Host, _, _ = net.SplitHostPort(r.Host)
	}
	if auth.Realm != r.Host {
		w.WriteHeader(bsfResultInvalidRequest)
		return
	}

	var auts []byte
	if auth.Auts != "" {
		auts, e = base64.StdEncoding.DecodeString(auth.Auts)
		if e != nil || len(auts) != 14 {
			w.WriteHeader(bsfResultInvalidRequest)
			return
		}
	}

	btid := makeBTID(auth)
	av, ttl, e := getCachedAV(btid)

	if auth.Response != [16]byte{} {
		if ttl.IsZero() {
			w.WriteHeader(bsfResultInvalidRequest)
			return
		}

		cres := auth.Response
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		auth.SetBootstrapNonce(av.RAND, av.AUTN)
		if auts != nil {
			av.RES = []byte{}
			ttl = time.Time{}
		}
		auth.SetResponse(r.Method, av.RES, body)

		if auth.Response != cres {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else if auts != nil {
		w.WriteHeader(bsfResultInvalidRequest)
		return
	}

	if ttl.IsZero() {
		av, e = MultimediaAuthRequest(auth.Username, av.RAND, auts)
		if e != nil {
			w.WriteHeader(bsfResultUnableToGetAV)
			return
		}
		av.IMPI = auth.Username
		auth.SetBootstrapNonce(av.RAND, av.AUTN)
		btid = makeBTID(auth)

		ttl = time.Now().Add(expiration).UTC()
		setCachedAV(btid, av, ttl)
	} else {
		auth.SetBootstrapNonce(av.RAND, av.AUTN)
	}

	if auth.Response == [16]byte{} || auts != nil {
		w.Header().Set("WWW-Authenticate", WWWAuthenticate{
			Realm:     r.Host,
			Nonce:     auth.Nonce,
			Qop:       qop,
			Opaque:    NewRandText(),
			Algorithm: "AKAv1-MD5"}.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	/*
		body, e := xml.Marshal(av)
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body = append([]byte(xml.Header), body...)
	*/
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<BootstrappingInfo xmlns="uri:3gpp-gba">` +
		`<btid>` + btid + `</btid>` +
		`<lifetime>` + ttl.Format(time.RFC3339) + `</lifetime>` +
		`</BootstrappingInfo>`)

	w.Header().Set("Expires", ttl.Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/vnd.3gpp.bsf+xml")
	/*
		auth.SetResponse("", av.RES, body)
		w.Header().Set("Authentication-Info", AuthenticationInfo{
			Nextnonce: base64.StdEncoding.EncodeToString(append(av.RAND, av.AUTN...)),
			Qop:       auth.Qop,
			Rspauth:   auth.Response,
			Cnonce:    auth.Cnonce,
			Nc:        auth.Nc}.String())
	*/
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

/*
	func KeyDerivationFromCache(btid string, naf string, vid uint8, pid uint32) []byte {
		av, _ := getCachedAV(btid)
		if av.RAND == nil {
			return nil
		}
		return KeyDerivation(av.CK, av.IK, av.RAND, av.IMPI, naf, vid, pid)
	}
*/
func KeyDerivation(ck, ik, rand []byte, impi, naf string, vid uint8, pid uint32) []byte {
	buf := new(bytes.Buffer)
	// FC
	buf.WriteByte(0x01)
	// P0 = "gba-me", L0 = 6 octets
	buf.WriteString("gba-me")
	binary.Write(buf, binary.BigEndian, uint16(len("bga-me")))
	// P1 = RAND, L1 = length of RAND (16 octets)
	buf.Write(rand)
	binary.Write(buf, binary.BigEndian, uint16(len(rand)))
	// P2 = IMPI encoded to an octet string using UTF-8 encoding
	// L2 = length of IMPI (not greater than 65535)
	buf.WriteString(impi)
	binary.Write(buf, binary.BigEndian, uint16(len(impi)))
	// P3 = NAF_ID with the FQDN part of the NAF_ID encoded to an octet string using UTF-8 encoding
	// L3 = length of NAF_ID (not greater than 65535)
	buf.WriteString(naf)
	binary.Write(buf, binary.BigEndian, vid)
	binary.Write(buf, binary.BigEndian, pid)
	binary.Write(buf, binary.BigEndian, uint16(len(naf)+5))

	mac := hmac.New(sha256.New, append(ck, ik...))
	buf.WriteTo(mac)
	return mac.Sum(nil)
}
