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
	"time"

	"github.com/fkgi/bag"
	"github.com/fkgi/diameter"
	"github.com/fkgi/diameter/connector"
)

func main() {
	host, err := os.Hostname()
	if err != nil {
		host = "hub.internal"
	}
	dl := flag.String("diameter-local", host,
		"Diameter local host with format [tcp|sctp://][realm/]hostname[:port].")
	dp := flag.String("diameter-peer", "",
		"Diameter peer host with format [tcp|sctp://][realm/]hostname[:port].")
	bl := flag.String("bsf-local", ":80", "BSF HTTP local host with format [host][:port].")
	nl := flag.String("naf-local", ":80", "NAF HTTP local host with format [host][:port].")
	flag.Parse()

	connector.TermSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, os.Interrupt}
	marHandler := connector.Handle(303, 16777221, 10415, nil)

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

	cache := map[string]AvChache{}

	bag.GetAV = func(s string) (av bag.AV) {
		if avc, ok := cache[s]; ok && avc.expire.After(time.Now()) {
			av = avc.AV
			return
		}
		_, avps := marHandler(false, []diameter.AVP{
			diameter.SetSessionID(diameter.NextSession(diameter.Host.String())),
			diameter.SetAuthSessionState(false),
			diameter.SetVendorSpecAppID(10415, 16777221),
			diameter.SetOriginHost(diameter.Host),
			diameter.SetOriginRealm(diameter.Realm),
			diameter.SetDestinationRealm(diameter.Realm),
			diameter.SetUserName(s)})
		//var result uint32
		for _, a := range avps {
			switch a.Code {
			case 268:
				// result, _ = diameter.GetResultCode(a)
			case 612:
				av.RAND, av.AUTN, _, av.RES, av.CK, av.IK, _ = bag.GetSIPAuthDataItem(a)
			}
		}
		cache[s] = AvChache{AV: av, expire: time.Now().Add(time.Second * 10)}
		return
	}

	ch := make(chan error)
	go func() {
		log.Println("connecting DIAMETER from", *dl, "to", *dp)
		ch <- errors.Join(errors.New("DIAMETER is closed"),
			connector.DialAndServe(*dl, *dp))
	}()
	go func() {
		ch <- errors.Join(errors.New("BSF HTTP is closed"),
			http.ListenAndServe(*bl, http.HandlerFunc(bag.BootstrapHandler)))
	}()
	go func() {
		ch <- errors.Join(errors.New("NAF HTTP is closed"),
			http.ListenAndServe(*nl, http.HandlerFunc(bag.ApplicationHandler)))
	}()
	log.Println(<-ch)
}

type AvChache struct {
	bag.AV
	expire time.Time
}
