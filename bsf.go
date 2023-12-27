package bag

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

type AV struct {
	RAND    []byte // 128 bit AKA RAND
	AUTN    []byte // SQN(48)+AMF(16)+MAC(64)=128 bit AKA AUTN
	RES     []byte // 128 bit AKA RES
	IK      []byte // 128 bit AKA IK
	CK      []byte // 128 bit AKA CK
	Expires time.Time
	Host    string
}

func (a *AV) UnmarshalJSON(b []byte) (e error) {
	var tmp struct {
		RAND string
		AUTN string
		RES  string
		IK   string
		CK   string
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
		RAND string
		AUTN string
		RES  string
		IK   string
		CK   string
	}
	return json.Marshal(tmp{
		RAND: hex.EncodeToString(a.RAND),
		AUTN: hex.EncodeToString(a.AUTN),
		RES:  hex.EncodeToString(a.RES),
		IK:   hex.EncodeToString(a.IK),
		CK:   hex.EncodeToString(a.CK)})
}

func (a AV) String() string {
	return fmt.Sprintf(
		"RAND=%x, AUTN=%x, RES=%x, IK=%x, CK=%x",
		a.RAND, a.AUTN, a.RES, a.IK, a.CK)
}

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

var GetAV func(string) (AV, error)

func BootstrapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", productName+" BSF")
	auth, e := ParseaAuthorization(r.Header.Get("Authorization"))
	if e != nil || auth.Username == "" || auth.Realm == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	av, e := GetAV(auth.Username)
	if e != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if auth.Response == [16]byte{} {
		w.Header().Set("WWW-Authenticate", WWWAuthenticate{
			Realm:     r.Host,
			Nonce:     base64.StdEncoding.EncodeToString(append(av.RAND, av.AUTN...)),
			Qop:       qop,
			Opaque:    NewRandText(),
			Algorithm: "AKAv1-MD5"}.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	av.Expires = time.Now().Add(expiration)
	av.Host = r.Host
	body, e := xml.Marshal(av)
	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	body = append([]byte(xml.Header), body...)
	auth.SetResponse("", av.RES, body)

	w.Header().Set("Expires", av.Expires.UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/vnd.3gpp.bsf+xml")
	w.Header().Set("Authentication-Info", AuthenticationInfo{
		Nextnonce: base64.StdEncoding.EncodeToString(append(av.RAND, av.AUTN...)),
		Qop:       auth.Qop,
		Rspauth:   auth.Response,
		Cnonce:    auth.Cnonce,
		Nc:        auth.Nc}.String())
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func KeyDerivation(ck, ik, rand []byte, impi, naf string, vid uint8, protoid uint32) []byte {
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
	binary.Write(buf, binary.BigEndian, protoid)
	binary.Write(buf, binary.BigEndian, uint16(len(naf)+5))

	mac := hmac.New(sha256.New, append(ck, ik...))
	buf.WriteTo(mac)
	return mac.Sum(nil)
}
