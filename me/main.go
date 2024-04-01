package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fkgi/bag/common"
)

var (
	bsf = "http://bsf.mnc99.mcc999.pub.3gppnetwork.org"

	authRetransmit = 3
	expire         = time.Second * 3

	client *http.Client
)

const uaPrefix = ""

func main() {
	fmt.Println("[INFO]", "starting GBA_ME tester")

	flag.StringVar(&bsf, "bsf", bsf, "HTTP URL of BSF")
	db := flag.String("db", "localhost:6636", "DB RPC remote host:port")
	local := flag.String("ctrl", os.TempDir()+string(os.PathSeparator)+"me.sock", "ctrl RPC local UNIX socket path")
	secrets := flag.String("secrets", "", "TLS secrets file for capture")

	ciphers := ""
	allCiphers := map[string]*tls.CipherSuite{}
	for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		allCiphers[c.Name] = c
		ciphers += "," + c.Name
	}
	ciphers = ciphers[1:]
	flag.StringVar(&ciphers, "ciphers", ciphers, "comma separated names of ciphers for TLS")

	flag.Parse()

	if u, e := url.Parse(bsf); e != nil || u.Host == "" || u.Scheme == "" {
		fmt.Fprintln(os.Stderr, "[ERR]", "invalid BSF URL:", bsf)
		os.Exit(1)
	}

	t := http.DefaultTransport.(*http.Transport)
	t = t.Clone()
	t.TLSClientConfig.CipherSuites = []uint16{}
	for _, c := range strings.Split(ciphers, ",") {
		cipher, ok := allCiphers[c]
		if !ok {
			fmt.Fprintln(os.Stderr, "[ERR]", "unknown TLS cipher:", c)
			os.Exit(1)
		}
		t.TLSClientConfig.CipherSuites = append(
			t.TLSClientConfig.CipherSuites, cipher.ID)
	}
	//	0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0xc012}
	t.TLSClientConfig.InsecureSkipVerify = true
	t.TLSClientConfig.MaxVersion = tls.VersionTLS12
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	if *secrets != "" {
		var e error
		t.TLSClientConfig.KeyLogWriter, e = os.OpenFile(*secrets, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if e != nil {
			fmt.Fprintln(os.Stderr, "[ERR]", "failed to create TLS secrets file:", e)
			os.Exit(1)
		}
	}
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	client = &http.Client{Timeout: expire, Transport: t}

	common.Log = func(a ...any) {
		if len(a) == 0 {
			fmt.Println()
		} else if a[0] == "[ERR]" {
			fmt.Fprintln(os.Stderr, a...)
		} else if a[0] == "[INFO]" {
			fmt.Println(a...)
		}
	}
	go common.ConnectDB(*db)

	fmt.Println("[INFO]", "listening ctrl RPC request on", *local)
	l, e := net.Listen("unix", *local)
	if e != nil {
		fmt.Fprintln(os.Stderr, "[ERR]", "failed to listen ctrl RPC session:", e)
		os.Exit(1)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(l net.Listener, c chan os.Signal) {
		sig := <-c
		fmt.Println("\n", "[INFO]", "caught signal", sig.String(), "shutting down")
		l.Close()
		os.Exit(0)
	}(l, sigc)

	for {
		c, e := l.Accept()
		if e != nil {
			fmt.Fprintln(os.Stderr, "[ERR]", "failed to accept ctrl RPC session:", e)
			l.Close()
			os.Exit(1)
		}
		go gbaClientSession(c)
	}
}
