package main

import (
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/fkgi/bag"
)

var avs = make(chan (map[string]bag.AV), 1)

func init() {
	avs <- map[string]bag.AV{}
}

func main() {
	hport := flag.String("api-port", ":8080", "HTTP API local port with format [host]:port")
	cport := flag.String("rpc-port", ":6636", "DB RPC local port with format [host]:port")
	flag.Parse()

	log.Println("[INFO]", "starting authentication vector DB")

	log.Println("[INFO]", "listening DB RPC on", *cport)
	l, e := net.Listen("tcp", *cport)
	if e != nil {
		log.Fatalln("[ERR]", "failed to listen DB RPC:", e)
	}
	defer l.Close()
	go func(l net.Listener) {
		c, e := l.Accept()
		for ; e == nil; c, e = l.Accept() {
			go rpcHandler(c)
		}
		log.Fatalln("[ERR]", "failed to accept DB RPC:", e)
	}(l)

	log.Println("[INFO]", "listening HTTP request on", *hport)
	log.Fatalln("[ERR]", "failed to serve HTTP:",
		http.ListenAndServe(*hport, http.HandlerFunc(apiHandler)))
}

func rpcHandler(c net.Conn) {
	log.Println("[INFO]", "new DB RPC connection from", c.RemoteAddr())
	dec := gob.NewDecoder(c)
	enc := gob.NewEncoder(c)

	for {
		r := ""
		if e := dec.Decode(&r); e == io.EOF {
			break
		} else if e != nil {
			log.Println("[ERR]", "RPC request decoding failed:", e)
			break
		}

		av := <-avs
		e := enc.Encode(av[r])
		avs <- av
		if e != nil {
			log.Println("[ERR]", "RPC answer encoding failed:", e)
			break
		}
	}

	c.Close()
	log.Println("[INFO]", "RPC connection from", c.RemoteAddr(), "closed")
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "" || r.URL.Path == "/" {
		switch r.Method {
		case http.MethodGet:
			avm := <-avs
			data, e := json.Marshal(avm)
			avs <- avm
			if e != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(e.Error()))
				log.Println("[ERR]", "prov fail:", "failed to marshal data list:", e)
			} else {
				w.Header().Add("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write(data)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	p := strings.Split(r.URL.Path, "/")
	if len(p) != 2 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("invalid path"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		avm := <-avs
		av, ok := avm[p[1]]
		avs <- avm
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("unknown IMPI: " + p[1]))
		} else if data, e := json.Marshal(av); e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(e.Error()))
			log.Println("[ERR]", "prov fail:", "failed to marshal data for", p[1], ":", e)
		} else {
			w.Header().Add("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(data)
		}

	case http.MethodPut:
		var av bag.AV
		if data, e := io.ReadAll(r.Body); e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(e.Error()))
			log.Println("[ERR]", "prov fail:", "failed to read PUT data for", p[1], ":", e)
		} else if e = json.Unmarshal(data, &av); e != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(e.Error()))
			log.Println("[ERR]", "prov fail:", "failed to unmarshal data for", p[1], ":", e)
		} else {
			av.IMPI = p[1]
			if len(av.RAND) == 0 {
				av.RAND = make([]byte, 16)
				rand.Read(av.RAND)
			}
			if len(av.AUTN) == 0 {
				av.AUTN = make([]byte, 16)
				rand.Read(av.AUTN)
			}
			if len(av.RES) == 0 {
				av.RES = make([]byte, 16)
				rand.Read(av.RES)
			}
			if len(av.IK) == 0 {
				av.IK = make([]byte, 16)
				rand.Read(av.IK)
			}
			if len(av.CK) == 0 {
				av.CK = make([]byte, 16)
				rand.Read(av.CK)
			}
			avm := <-avs
			avm[p[1]] = av
			avs <- avm

			w.Header().Add("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(data)
		}
		r.Body.Close()

	case http.MethodDelete:
		avm := <-avs
		if _, ok := avm[p[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("unknown IMPI: " + p[1]))
		} else {
			delete(avm, p[1])
			w.WriteHeader(http.StatusNoContent)
		}
		avs <- avm

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
