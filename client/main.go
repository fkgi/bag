package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fkgi/bag"
)

var (
	impi = "999991122223333@ims.mnc99.mcc999.3gppnetwork.org"
	impu = "sip:+9991122223333@ims.mnc99.mcc999.3gppnetwork.org"

	bsf = "http://bsf.mnc99.mcc999.pub.3gppnetwork.org"
	naf = "http://naf.mnc99.mcc999.pub.3gppnetwork.org"
	hss = "http://hss.mnc99.mcc999.pub.3gppnetwork.org"

	authRetransmit = 3
	expire         = time.Second * 3

	av = bag.AV{
		RAND: make([]byte, 16),
		AUTN: make([]byte, 16),
		RES:  make([]byte, 16),
		IK:   make([]byte, 16),
		CK:   make([]byte, 16)}

	client *http.Client
)

const uaPrefix = ""

func fatalLog(v ...any) {
	fmt.Fprintln(os.Stderr, v...)
	os.Exit(1)
}

func main() {
	flag.StringVar(&impi, "i", impi, "IMPI")
	flag.StringVar(&impu, "u", impu, "IMPU")
	flag.StringVar(&bsf, "b", bsf, "BSF URL")
	flag.StringVar(&naf, "n", naf, "NAF URL")
	flag.StringVar(&hss, "h", hss, "HSS URL")

	local := "localhost:8080"
	flag.StringVar(&local, "l", local, "listening address for HTTP proxy")

	secrets := ""
	flag.StringVar(&secrets, "s", secrets, "TLS secrets file for capture")

	ciphers := ""
	allCiphers := map[string]*tls.CipherSuite{}
	for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		allCiphers[c.Name] = c
		ciphers += "," + c.Name
	}
	ciphers = ciphers[1:]
	flag.StringVar(&ciphers, "c", ciphers, "ciphers for TLS")

	flag.Parse()

	if u, e := url.Parse(bsf); e != nil || u.Host == "" || u.Scheme == "" {
		fatalLog("[ERR]", "invalid BSF URL:", bsf)
	}
	if u, e := url.Parse(naf); e != nil || u.Host == "" || u.Scheme == "" {
		fatalLog("[ERR]", "invalid NAF URL:", naf)
	}

	t := http.DefaultTransport.(*http.Transport)
	t = t.Clone()
	t.TLSClientConfig.CipherSuites = []uint16{}
	for _, c := range strings.Split(ciphers, ",") {
		cipher, ok := allCiphers[c]
		if !ok {
			fatalLog("[ERR]", "unknown TLS cipher:", c)
		}
		t.TLSClientConfig.CipherSuites = append(
			t.TLSClientConfig.CipherSuites, cipher.ID)
	}
	//	0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0xc012}
	t.TLSClientConfig.InsecureSkipVerify = true
	t.TLSClientConfig.MaxVersion = tls.VersionTLS12
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	if secrets != "" {
		var e error
		t.TLSClientConfig.KeyLogWriter, e = os.OpenFile(secrets, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if e != nil {
			fatalLog("[ERR]", "failed to create TLS secrets file:", e)
		}
	}
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	client = &http.Client{Timeout: expire, Transport: t}

	fmt.Println("[INFO]", "registering authantication vector for", impi)
	rand.Read(av.RAND)
	fmt.Printf("  RAND = %x\n", av.RAND)
	rand.Read(av.AUTN)
	fmt.Printf("  AUTN = %x\n", av.AUTN)
	rand.Read(av.RES)
	fmt.Printf("  RES  = %x\n", av.RES)
	rand.Read(av.IK)
	fmt.Printf("  IK   = %x\n", av.IK)
	rand.Read(av.CK)
	fmt.Printf("  CK   = %x\n", av.CK)
	registerAV()

	ch := make(chan error)
	fmt.Println("[INFO]", "listening HTTP request on", local)
	go func() {
		ch <- fmt.Errorf("HTTP is closed: %s",
			http.ListenAndServe(local, http.HandlerFunc(gbaClientHandler)))
	}()
	fatalLog("[ERR]", <-ch)
}

func registerAV() {
	if d, e := json.Marshal(av); e != nil {
		fatalLog("[ERR]", "failed register authentication vector:", e)
	} else if req, e := http.NewRequest(http.MethodPut, hss+"/"+impi, bytes.NewBuffer(d)); e != nil {
		fatalLog("[ERR]", "failed register authentication vector:", e)
	} else if res, e := new(http.Client).Do(req); e != nil {
		fatalLog("[ERR]", "failed register authentication vector:", e)
	} else if res.StatusCode != http.StatusOK {
		fatalLog("[ERR]", "failed register authentication vector:", "server returns", res.Status)
	}
}
