package bag

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

type AV struct {
	RAND []byte // 128 bit AKA RAND
	AUTN []byte // SQN(48)+AMF(16)+MAC(64)=128 bit AKA AUTN
	RES  []byte // 128 bit AKA RES
	IK   []byte // 128 bit AKA IK
	CK   []byte // 128 bit AKA CK
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

type BootstrappingInfo struct {
	Xmlns   string `xml:"xmlns,attr"`
	BTID    string `xml:"btid"`
	Liftime string `xml:"lifetime"`
}

var GetAV func(string) AV

func BootstrapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", productName+" BSF")
	auth, e := ParseaAuthorization(r.Header.Get("Authorization"))
	if e != nil || auth.Username == "" || auth.Realm == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	av := GetAV(auth.Username)

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

	body, e := xml.Marshal(BootstrappingInfo{
		Xmlns:   "uri:3gpp-gba",
		BTID:    base64.StdEncoding.EncodeToString(av.RAND) + "@" + r.Host,
		Liftime: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	body = append([]byte(xml.Header), body...)
	auth.SetResponse("", hex.EncodeToString(av.RES), body)

	w.Header().Set("Expires", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
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
