package bag

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

func parseDigestPrefix(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(s), "digest") {
		return nil, errors.New("invalid auth scheme")
	}
	buf := strings.NewReader(s[6:])
	c, _, e := buf.ReadRune()
	if e != nil {
		return nil, e
	}
	if !unicode.IsSpace(c) {
		return nil, errors.New("invalid auth scheme")
	}
	return parseParam(buf)
}

func parseParam(buf *strings.Reader) (map[string]string, error) {
	ret := make(map[string]string)
	c, _, e := buf.ReadRune()
	for {
		for ; e == nil; c, _, e = buf.ReadRune() {
			if !unicode.IsSpace(c) {
				break
			}
		}
		if e == io.EOF {
			return ret, nil
		} else if e != nil {
			return nil, e
		}

		name := new(bytes.Buffer)
		for ; e == nil; c, _, e = buf.ReadRune() {
			if ('a' <= c && c <= 'z') ||
				('A' <= c && c <= 'Z') ||
				('0' <= c && c <= '9') ||
				c == '-' {
				name.WriteRune(c)
			} else {
				break
			}
		}
		if e == io.EOF {
			return ret, nil
		} else if e != nil {
			return nil, e
		}

		for ; e == nil; c, _, e = buf.ReadRune() {
			if c == '=' {
				c, _, e = buf.ReadRune()
				break
			}
			if !unicode.IsSpace(c) {
				e = errors.New("unexpected rune")
				break
			}
		}
		if e == io.EOF {
			return ret, nil
		} else if e != nil {
			return nil, e
		}

		for ; e == nil; c, _, e = buf.ReadRune() {
			if !unicode.IsSpace(c) {
				break
			}
		}
		if e == io.EOF {
			return ret, nil
		} else if e != nil {
			return nil, e
		}

		value := new(bytes.Buffer)
		if c == '"' {
			c, _, e = buf.ReadRune()
			for ; e == nil; c, _, e = buf.ReadRune() {
				if c == '"' {
					c, _, e = buf.ReadRune()
					break
				}
				value.WriteRune(c)
			}
		} else {
			for ; e == nil; c, _, e = buf.ReadRune() {
				if ('a' <= c && c <= 'z') ||
					('A' <= c && c <= 'Z') ||
					('0' <= c && c <= '9') ||
					c == '!' || c == '#' || c == '$' ||
					c == '%' || c == '&' || c == '\'' ||
					c == '*' || c == '+' || c == '-' ||
					c == '.' || c == '^' || c == '_' ||
					c == '`' || c == '|' || c == '~' {
					value.WriteRune(c)
				} else {
					break
				}
			}
		}
		ret[name.String()] = value.String()
		if e == io.EOF {
			return ret, nil
		} else if e != nil {
			return nil, e
		}

		for ; e == nil; c, _, e = buf.ReadRune() {
			if c == ',' {
				c, _, e = buf.ReadRune()
				break
			}
			if !unicode.IsSpace(c) {
				e = errors.New("unexpected rune")
				break
			}
		}
		if e == io.EOF {
			return ret, nil
		} else if e != nil {
			return nil, e
		}
	}
}

type WWWAuthenticate struct {
	Realm     string // mandatory
	Domain    []string
	Nonce     string // mandatory
	Opaque    string
	Stale     bool     // not quoted
	Algorithm string   // not quoted
	Qop       []string //mandatory
	// Charset string
	// Userhash bool
}

func ParseaWWWAuthenticate(s string) (a WWWAuthenticate, e error) {
	p, e := parseDigestPrefix(s)
	if e != nil {
		return
	}

	var ok bool
	a.Realm, ok = p["realm"]
	if !ok {
		e = errors.New("realm not found")
		return
	}
	if p["domain"] != "" {
		a.Domain = strings.Fields(p["domain"])
	}
	a.Nonce, ok = p["nonce"]
	if !ok {
		e = errors.New("nonce not found")
		return
	}
	a.Opaque = p["opaque"]
	a.Stale = p["stale"] == "true"
	a.Algorithm = p["algorithm"]
	qop, ok := p["qop"]
	if !ok {
		e = errors.New("qop not found")
		return
	}
	a.Qop = strings.Split(qop, ",")
	for i := range a.Qop {
		a.Qop[i] = strings.TrimSpace(a.Qop[i])
		if a.Qop[i] == "" {
			e = errors.New("invalid qop")
		}
	}
	return
}

func (a WWWAuthenticate) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `Digest realm="%s"`, a.Realm)
	if len(a.Domain) != 0 {
		fmt.Fprint(buf, `, domain="`)
		for _, s := range a.Domain {
			fmt.Fprint(buf, s)
			fmt.Fprint(buf, " ")
		}
		fmt.Fprint(buf, `"`)
	}
	fmt.Fprintf(buf, `, nonce="%s"`, a.Nonce)
	if a.Opaque != "" {
		fmt.Fprintf(buf, `, opaque="%s"`, a.Opaque)
	}
	if a.Stale {
		fmt.Fprintf(buf, `, stale=%t`, a.Stale)
	}
	if a.Algorithm != "" {
		fmt.Fprintf(buf, `, algorithm=%s`, a.Algorithm)
	}
	if len(a.Qop) != 0 {
		fmt.Fprint(buf, `, qop="`)
		for i, s := range a.Qop {
			fmt.Fprintf(buf, `%s`, s)
			if i+1 < len(a.Qop) {
				fmt.Fprintf(buf, `,`)
			}
		}
	}
	fmt.Fprint(buf, `"`)
	return buf.String()
}

type Authorization struct {
	Username  string   // mandatory
	Realm     string   // mandatory
	Nonce     string   // mandatory
	Uri       string   // mandatory
	Response  [16]byte // mandatory
	Algorithm string   // not quoted
	Cnonce    string
	Opaque    string
	Qop       string // mandatory, not quoted
	Nc        uint64 // not quoted
	// Userhash bool
	Auts string
}

func ParseaAuthorization(s string) (a Authorization, e error) {
	p, e := parseDigestPrefix(s)
	if e != nil {
		return
	}

	var ok bool
	a.Username, ok = p["username"]
	if !ok {
		e = errors.New("username not found")
		return
	}
	a.Realm, ok = p["realm"]
	if !ok {
		e = errors.New("realm not found")
		return
	}
	a.Nonce, ok = p["nonce"]
	if !ok {
		e = errors.New("nonce not found")
		return
	}
	a.Uri, ok = p["uri"]
	if !ok {
		e = errors.New("uri not found")
		return
	}
	res, ok := p["response"]
	if !ok {
		e = errors.New("response not found")
		return
	}
	if tmp, err := hex.DecodeString(res); err != nil {
		e = errors.New("invalid response value")
		return
	} else {
		copy(a.Response[:], tmp)
	}
	a.Algorithm = p["algorithm"]
	a.Cnonce = p["cnonce"]
	a.Opaque = p["opaque"]
	a.Qop = p["qop"]
	a.Nc, _ = strconv.ParseUint(p["nc"], 16, 64)
	a.Auts = p["auts"]
	return
}

func (a Authorization) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `Digest username="%s", realm="%s", nonce="%s", uri="%s"`,
		a.Username, a.Realm, a.Nonce, a.Uri)
	if a.Response == [16]byte{} {
		fmt.Fprint(buf, `, response=""`)
	} else {
		fmt.Fprintf(buf, `, response="%x"`, a.Response)
	}
	if a.Algorithm != "" {
		fmt.Fprintf(buf, `, algorithm=%s`, a.Algorithm)
	}
	if a.Cnonce != "" {
		fmt.Fprintf(buf, `, cnonce="%s"`, a.Cnonce)
	}
	if a.Opaque != "" {
		fmt.Fprintf(buf, `, opaque="%s"`, a.Opaque)
	}
	if a.Qop != "" {
		fmt.Fprintf(buf, `, qop=%s`, a.Qop)
	}
	if a.Nc != 0 {
		fmt.Fprintf(buf, `, nc=%08x`, a.Nc)
	}
	if a.Auts != "" {
		fmt.Fprintf(buf, `, auts="%s"`, a.Auts)
	}
	return buf.String()
}

func (a *Authorization) SetResponse(method string, pwd, body []byte) {
	a1 := md5.Sum(append([]byte(a.Username+":"+a.Realm+":"), pwd...))
	a2 := md5.Sum(body)
	if a.Qop == "auth-int" {
		a2 = md5.Sum([]byte(fmt.Sprintf("%s:%s:%s",
			method, a.Uri, hex.EncodeToString(a2[:]))))
	} else {
		a2 = md5.Sum([]byte(fmt.Sprintf("%s:%s", method, a.Uri)))
	}
	a.Response = md5.Sum([]byte(fmt.Sprintf("%x:%s:%08x:%s:%s:%x",
		a1, a.Nonce, a.Nc, a.Cnonce, a.Qop, a2)))
}

type AuthenticationInfo struct {
	Nextnonce string //mandatory
	Qop       string //mandatory, not quoted
	Rspauth   [16]byte
	Cnonce    string
	Nc        uint64 // not quoted
}

func ParseaAuthenticationInfo(s string) (a AuthenticationInfo, e error) {
	p, e := parseParam(strings.NewReader(strings.TrimSpace(s)))
	if e != nil {
		return
	}

	var ok bool
	a.Nextnonce, ok = p["nextnonce"]
	if !ok {
		e = errors.New("nextnonce not found")
		return
	}
	a.Qop, ok = p["qop"]
	if !ok {
		e = errors.New("qop not found")
		return
	}
	if tmp, e := hex.DecodeString(p["rspauth"]); e == nil {
		copy(a.Rspauth[:], tmp)
	}
	a.Cnonce = p["cnonce"]
	a.Nc, _ = strconv.ParseUint(p["nc"], 16, 64)
	return
}

func (a AuthenticationInfo) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `nextnonce="%s"`, a.Nextnonce)
	if a.Qop != "" {
		fmt.Fprintf(buf, `, qop=%s`, a.Qop)
	}
	if a.Rspauth != [16]byte{} {
		fmt.Fprintf(buf, `, rspauth="%x"`, a.Rspauth)
	}
	if a.Cnonce != "" {
		fmt.Fprintf(buf, `, cnonce="%s"`, a.Cnonce)
	}
	if a.Nc != 0 {
		fmt.Fprintf(buf, `, nc=%08x`, a.Nc)
	}
	return buf.String()
}
