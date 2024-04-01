package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/fkgi/bag/common"
	"github.com/fkgi/diameter"
	"github.com/fkgi/diameter/connector"
)

var (
	verbose *bool
)

func main() {
	log.Println("[INFO]", "starting Multimedia-Auth HSS")

	host, e := os.Hostname()
	if e != nil {
		host = "hub.internal"
	}
	dl := flag.String("diameter-local", host,
		"DIAMETER local host with format [tcp|sctp://][realm/]hostname[:port]")
	dp := flag.String("diameter-peer", "",
		"DIAMETER peer host for dial with format as same as -diameter-local")
	db := flag.String("db", "localhost:6636", "DB RPC remote host:port")
	verbose = flag.Bool("verbose", false, "verbose log mode")
	flag.Parse()

	connector.TermSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, os.Interrupt}
	connector.Handle(303, 16777221, 10415, marHandler)

	connector.TransportUpNotify = func(c net.Conn) {
		buf := new(strings.Builder)
		fmt.Fprintln(buf, "[INFO] transport connection up")
		fmt.Fprintln(buf, "  | local address: ", c.LocalAddr())
		fmt.Fprintln(buf, "  | remote address:", c.RemoteAddr())
		log.Print(buf)
	}
	diameter.ConnectionUpNotify = func(c *diameter.Connection) {
		buf := new(strings.Builder)
		fmt.Fprintln(buf, "[INFO] DIAMETER connection up")
		fmt.Fprintln(buf, "  | local host/realm:", diameter.Host, "/", diameter.Realm)
		fmt.Fprintln(buf, "  | peer host/realm: ", c.Host, "/", c.Realm)
		log.Print(buf)
	}

	if *verbose {
		diameter.TraceEvent = func(old, new, event string, e error) {
			log.Println("[INFO]", "DIAMETER state update:",
				old, "->", new, "by event", event, "with error", e)
		}
		diameter.TraceMessage = func(msg diameter.Message, dct diameter.Direction, e error) {
			buf := new(strings.Builder)
			fmt.Fprintf(buf, "[INFO] %s DIAMETER message handling: error=%v", dct, e)
			fmt.Fprintln(buf, msg)
			log.Print(buf)
		}
	}

	common.Log = func(a ...any) {
		if len(a) != 0 {
			log.Println(a...)
		}
	}
	go common.ConnectDB(*db)

	log.Println("[INFO]", "connecting DIAMETER from", *dl, "to", *dp)
	log.Println("[ERR]", "DIAMETER is closed", connector.DialAndServe(*dl, *dp))
}
