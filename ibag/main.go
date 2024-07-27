package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/fkgi/bag"
	"github.com/fkgi/diameter"
	"github.com/fkgi/diameter/connector"
)

func main() {
	dl := flag.String("diameter-local", "", "Diameter local address")
	dp := flag.String("diameter-peer", "", "Diameter peer address")
	bl := flag.String("bsf-local", "", "BSF local IP address")
	nl := flag.String("naf-local", "", "NAF local IP address")
	cr := flag.String("crt", "", "TLS crt file")
	ky := flag.String("key", "", "TLS key file")
	flag.Parse()

	connector.TermSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, os.Interrupt}

	diameter.ConnectionUpNotify = func(c *diameter.Connection) {
		buf := new(strings.Builder)
		fmt.Fprintln(buf, "DIAMETER connection up")
		fmt.Fprintln(buf, "| local host/realm:", diameter.Host, "/", diameter.Realm)
		fmt.Fprintln(buf, "| peer host/realm: ", c.Host, "/", c.Realm)
		log.Print(buf)
	}

	ch := make(chan error)
	go func() {
		ch <- errors.Join(errors.New("DIAMETER is closed"), connector.DialAndServe(*dl, *dp))
	}()

	go func() {
		ch <- errors.Join(errors.New("BSF HTTP is closed"),
			http.ListenAndServe(*bl+":80", http.HandlerFunc(bag.BootstrapHandler)))
	}()
	go func() {
		svr := &http.Server{
			Addr:      *bl + ":443",
			Handler:   http.HandlerFunc(bag.BootstrapHandler),
			TLSConfig: &tls.Config{CipherSuites: []uint16{}},
		}
		for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			svr.TLSConfig.CipherSuites = append(svr.TLSConfig.CipherSuites, c.ID)
		}
		ch <- errors.Join(errors.New("BSF HTTPs is closed"),
			svr.ListenAndServeTLS(*cr, *ky))
	}()

	go func() {
		ch <- errors.Join(errors.New("NAF HTTP is closed"),
			http.ListenAndServe(*nl+":80", http.HandlerFunc(bag.ApplicationHandler)))
	}()
	go func() {
		svr := &http.Server{
			Addr:      *nl + ":443",
			Handler:   http.HandlerFunc(bag.ApplicationHandler),
			TLSConfig: &tls.Config{CipherSuites: []uint16{}},
		}
		for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			svr.TLSConfig.CipherSuites = append(svr.TLSConfig.CipherSuites, c.ID)
		}
		ch <- errors.Join(errors.New("NAF HTTPs is closed"),
			svr.ListenAndServeTLS(*cr, *ky))
	}()
	log.Println(<-ch)
}
