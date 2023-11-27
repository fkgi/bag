package bag

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
)

func ApplicationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", productName+" NAF")

	auth, e := ParseaAuthorization(r.Header.Get("Authorization"))
	if e != nil || auth.Username == "" || auth.Realm == "" {
		w.Header().Set("WWW-Authenticate", WWWAuthenticate{
			Algorithm: "MD5",
			Realm:     "3GPP-bootstrapping@" + r.Host,
			Nonce:     NewRandText(),
			Qop:       qop,
			Opaque:    NewRandText()}.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body := []byte("result")
	ks := []byte{0x00, 0x01}
	auth.SetResponse("", hex.EncodeToString(ks), body)

	w.Header().Set("Authentication-Info", AuthenticationInfo{
		Nextnonce: NewRandText(),
		Qop:       auth.Qop,
		Rspauth:   auth.Response,
		Cnonce:    auth.Cnonce,
		Nc:        auth.Nc}.String())
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func KeyDerivation(ck, ik, rand []byte, impi, nafID string) string {
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
	buf.WriteString(nafID)
	binary.Write(buf, binary.BigEndian, uint8(1))
	binary.Write(buf, binary.BigEndian, uint32(2))
	binary.Write(buf, binary.BigEndian, uint16(len(nafID)+5))

	mac := hmac.New(sha256.New, append(ck, ik...))
	mac.Write(buf.Bytes())
	return hex.EncodeToString(mac.Sum(nil))
}
