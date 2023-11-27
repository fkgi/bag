package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/fkgi/bag"
	"github.com/fkgi/diameter"
	"github.com/fkgi/diameter/connector"
)

var (
	avs = make(map[string]bag.AV)
)

func main() {
	log.Println("starting Multimedia-Auth HSS")

	host, err := os.Hostname()
	if err != nil {
		host = "hub.internal"
	}
	dl := flag.String("l", host,
		"DIAMETER local host with format [tcp|sctp://][realm/]hostname[:port].")
	dp := flag.String("p", "",
		"DIAMETER peer host for dial with format as same as -l.")
	hl := flag.String("a", ":8080", "HTTP local host with format [host][:port].")
	v := flag.Bool("v", false, "verbose mode.")
	flag.Parse()

	connector.TermSignals = []os.Signal{
		syscall.SIGINT, syscall.SIGTERM, os.Interrupt}
	connector.Handle(303, 16777221, 10415, marHandler)

	connector.TransportUpNotify = func(c net.Conn) {
		buf := new(strings.Builder)
		fmt.Fprintln(buf, "transport connection up")
		fmt.Fprintln(buf, "| local address: ", c.LocalAddr())
		fmt.Fprintln(buf, "| remote address:", c.RemoteAddr())
		log.Print(buf)
	}
	diameter.ConnectionUpNotify = func(c *diameter.Connection) {
		buf := new(strings.Builder)
		fmt.Fprintln(buf, "DIAMETER connection up")
		fmt.Fprintln(buf, "| local host/realm:", diameter.Host, "/", diameter.Realm)
		fmt.Fprintln(buf, "| peer host/realm: ", c.Host, "/", c.Realm)
		log.Print(buf)
	}
	if *v {
		diameter.TraceEvent = func(old, new, event string, err error) {
			log.Println("DIAMETER state update:",
				old, "->", new, "by event", event, "with error", err)
		}
		diameter.TraceMessage = func(msg diameter.Message, dct diameter.Direction, err error) {
			buf := new(strings.Builder)
			fmt.Fprintf(buf, "%s DIAMETER message handling: error=%v", dct, err)
			fmt.Fprintln(buf)
			fmt.Fprintln(buf, msg)
			log.Print(buf)
		}
	}

	ch := make(chan error)
	go func() {
		log.Println("connecting DIAMETER from", *dl, "to", *dp)
		ch <- errors.Join(errors.New("DIAMETER is closed"),
			connector.DialAndServe(*dl, *dp))
	}()
	go func() {
		log.Println("listening HTTP request on", *hl)
		ch <- errors.Join(errors.New("API HTTP is closed"),
			http.ListenAndServe(*hl, http.HandlerFunc(apiHandler)))
	}()
	log.Println(<-ch)
}
