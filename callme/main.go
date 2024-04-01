package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/fkgi/bag/common"
)

func main() {
	local := os.TempDir() + string(os.PathSeparator) + "me.sock"
	flag.StringVar(&local, "l", local, "UNIX socket path to me")

	r := common.MeReq{Method: "GET"}

	flag.StringVar(&r.Method, "X", r.Method, "HTTP request method")
	flag.StringVar(&r.RequestURI, "U", r.RequestURI, "HTTP request URI")
	data := ""
	flag.StringVar(&data, "d", data, "HTTP request body")

	flag.StringVar(&r.IMPI, "i", r.IMPI, "IMPI")
	flag.StringVar(&r.IMPU, "u", r.IMPU, "IMPU")
	flag.Parse()

	r.Body = []byte(data)

	r.Method = strings.ToUpper(r.Method)
	switch r.Method {
	case "GET", "PUT", "DELETE", "POST":
	default:
		fmt.Fprintln(os.Stderr, "invalid HTTP method:", r.Method)
		os.Exit(1)
	}

	if _, e := url.ParseRequestURI(r.RequestURI); e != nil {
		fmt.Fprintln(os.Stderr, "invalid HTTP URI:", r.RequestURI)
		os.Exit(1)
	}

	c, e := net.Dial("unix", local)
	if e != nil {
		fmt.Fprintln(os.Stderr, "faild to connect to GOB session:", e)
		os.Exit(1)
	}
	defer c.Close()

	dec := gob.NewDecoder(c)
	enc := gob.NewEncoder(c)

	e = enc.Encode(r)
	if e != nil {
		fmt.Fprintln(os.Stderr, "faild to encode request:", e)
		os.Exit(1)
	}

	a := common.MeAns{}
	e = dec.Decode(&a)
	if e != nil {
		fmt.Fprintln(os.Stderr, "faild to decode answer:", e)
		os.Exit(1)
	}

	fmt.Println(a.Code, http.StatusText(a.Code))
	fmt.Println(string(a.Body))
}
