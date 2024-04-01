package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/fkgi/diameter"
	"github.com/fkgi/diameter/connector"
)

var (
	dec     *gob.Decoder
	enc     *gob.Encoder
	verbose *bool
)

func main() {
	log.Println("[INFO] starting Multimedia-Auth HSS")

	host, err := os.Hostname()
	if err != nil {
		host = "hub.internal"
	}
	dl := flag.String("l", host,
		"DIAMETER local host with format [tcp|sctp://][realm/]hostname[:port].")
	dp := flag.String("p", "",
		"DIAMETER peer host for dial with format as same as -l.")
	db := flag.String("d", "localhost:6636", "DB RPC remote host:port.")

	verbose = flag.Bool("v", false, "verbose mode.")
	flag.Parse()

	connector.TermSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, os.Interrupt}
	connector.Handle(303, 16777221, 10415, marHandler)

	connector.TransportUpNotify = func(c net.Conn) {
		buf := new(strings.Builder)
		fmt.Fprintln(buf, "[INFO] transport connection up")
		fmt.Fprintln(buf, " | local address: ", c.LocalAddr())
		fmt.Fprintln(buf, " | remote address:", c.RemoteAddr())
		log.Print(buf)
	}
	diameter.ConnectionUpNotify = func(c *diameter.Connection) {
		buf := new(strings.Builder)
		fmt.Fprintln(buf, "[INFO] DIAMETER connection up")
		fmt.Fprintln(buf, " | local host/realm:", diameter.Host, "/", diameter.Realm)
		fmt.Fprintln(buf, " | peer host/realm: ", c.Host, "/", c.Realm)
		log.Print(buf)
	}

	if *verbose {
		diameter.TraceEvent = func(old, new, event string, err error) {
			log.Println("[INFO]", "DIAMETER state update:",
				old, "->", new, "by event", event, "with error", err)
		}
		diameter.TraceMessage = func(msg diameter.Message, dct diameter.Direction, err error) {
			buf := new(strings.Builder)
			fmt.Fprintf(buf, "[INFO] %s DIAMETER message handling: error=%v", dct, err)
			fmt.Fprintln(buf)
			fmt.Fprintln(buf, msg)
			log.Print(buf)
		}
	}

	log.Println("[INFO]", "connecting to DB RPC", *db)
	if c, e := net.Dial("tcp", *db); e != nil {
		log.Fatalln("[ERR]", "faild to connect to DB:", e)
	} else {
		defer c.Close()
		dec = gob.NewDecoder(c)
		enc = gob.NewEncoder(c)
	}

	log.Println("[INFO]", "connecting DIAMETER from", *dl, "to", *dp)
	log.Println("[ERR]", "DIAMETER is closed", connector.DialAndServe(*dl, *dp))
}
