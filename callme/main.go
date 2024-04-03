package main

import (
	"encoding/gob"
	"encoding/hex"
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
	flag.StringVar(&local, "rpc-sock", local, "ctrl RPC remote UNIX socket path")

	r := common.MeReq{Method: "GET"}
	flag.StringVar(&r.Method, "method", r.Method, "HTTP request method")
	flag.StringVar(&r.RequestURI, "uri", r.RequestURI, "HTTP request URI")
	flag.StringVar(&r.IMPI, "impi", r.IMPI, "IMPI")
	flag.StringVar(&r.IMPU, "impu", r.IMPU, "IMPU")
	body := flag.String("body", "", "HTTP request body")
	rand := flag.String("rand", "", "AV RAND value overwrite")
	autn := flag.String("autn", "", "AV AUTN value overwrite")
	res := flag.String("res", "", "AV RES value overwrite")
	ik := flag.String("ik", "", "AV IK value overwrite")
	ck := flag.String("ck", "", "AV CK value overwrite")
	flag.BoolVar(&r.ClearCache, "clear", false,
		"clear Authentication and B-TID chace in client")

	flag.Parse()

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

	r.Body = []byte(*body)
	var e error
	if *rand != "" {
		r.RAND, e = hex.DecodeString(*rand)
		if e != nil || len(r.RAND) != 16 {
			fmt.Fprintln(os.Stderr, "invalid RAND value:", e)
			os.Exit(1)
		}
	}
	if *autn != "" {
		r.AUTN, e = hex.DecodeString(*autn)
		if e != nil || len(r.AUTN) != 16 {
			fmt.Fprintln(os.Stderr, "invalid AUTN value:", e)
			os.Exit(1)
		}
	}
	if *res != "" {
		r.RES, e = hex.DecodeString(*res)
		if e != nil {
			fmt.Fprintln(os.Stderr, "invalid RES value:", e)
			os.Exit(1)
		}
	}
	if *ik != "" {
		r.IK, e = hex.DecodeString(*ik)
		if e != nil || len(r.IK) != 16 {
			fmt.Fprintln(os.Stderr, "invalid IK value:", e)
			os.Exit(1)
		}
	}
	if *ck != "" {
		r.CK, e = hex.DecodeString(*ck)
		if e != nil || len(r.CK) != 16 {
			fmt.Fprintln(os.Stderr, "invalid CK value:", e)
			os.Exit(1)
		}
	}

	c, e := net.Dial("unix", local)
	if e != nil {
		fmt.Fprintln(os.Stderr, "connect to ctrl RPC failed:", e)
		os.Exit(1)
	}
	defer c.Close()

	if e = gob.NewEncoder(c).Encode(r); e != nil {
		fmt.Fprintln(os.Stderr, "write to ctrl RPC failed:", e)
		os.Exit(1)
	}

	a := common.MeAns{}
	if e = gob.NewDecoder(c).Decode(&a); e != nil {
		fmt.Fprintln(os.Stderr, "read from ctrl RPC failed:", e)
		os.Exit(1)
	}
	fmt.Println(a.Code, http.StatusText(a.Code))
	fmt.Println(string(a.Body))
}
