package main

import (
	"encoding/csv"
	"encoding/gob"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fkgi/bag/common"
)

var (
	entry    = []common.MeReq{}
	stop     = false
	interval = 0
	reqCount = 0
	okCount  = 0
	ngCount  = 0
)

func main() {
	local := os.TempDir() + string(os.PathSeparator) + "me.sock"
	flag.StringVar(&local, "rpc-sock", local, "ctrl RPC remote UNIX socket path")
	list := flag.String("list", "./list.csv", "list file for subscriber")
	thread := flag.Int("thread", 10, "thread count")
	load := flag.Int("load", 100, "BGA request per second")
	flag.Parse()

	f, e := os.Open(*list)
	if e != nil {
		fmt.Fprintln(os.Stderr, "open list file failed:", e)
		os.Exit(1)
	}
	rdr := csv.NewReader(f)
	for r, e := rdr.Read(); e == nil; r, e = rdr.Read() {
		entry = append(entry, common.MeReq{
			Method:     r[2],
			RequestURI: r[3],
			IMPI:       r[0],
			IMPU:       r[1]})
	}
	f.Close()
	fmt.Println("[INFO]", "total", len(entry), "entries")

	interval = *load / *thread
	interval = 1000 / interval

	for i := 0; i < *thread; i++ {
		c, e := net.Dial("unix", local)
		if e != nil {
			fmt.Fprintln(os.Stderr, "connect to ctrl RPC failed:", e)
			os.Exit(1)
		}
		go run(c)
		time.Sleep(time.Second / time.Duration(*thread))
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(time.Second)
	ptotal := 0
	pok := 0
	png := 0
	fmt.Println("time,request total,request diff,ok answer total,ok answer diff,ng answer total,ng answer diff")
	for !stop {
		select {
		case <-sigc:
			stop = true
		case <-ticker.C:
			ctotal := reqCount
			cok := okCount
			cng := ngCount
			fmt.Println(time.Now(), ",", ctotal, ",", ctotal-ptotal, ",", cok, ",", cok-pok, ",", cng, ",", cng-png)
			ptotal = ctotal
			pok = cok
			png = cng
		}
	}
	ticker.Stop()
	fmt.Println("[INFO]", "caught stop signal, shutting down")
	time.Sleep(time.Second)
}

func run(c net.Conn) {
	dec := gob.NewDecoder(c)
	enc := gob.NewEncoder(c)
	a := common.MeAns{}
	ticker := time.NewTicker(time.Millisecond * time.Duration(interval))

	for !stop {
		<-ticker.C
		if e := enc.Encode(entry[rand.Intn(len(entry))]); e != nil {
			fmt.Fprintln(os.Stderr, "write to ctrl RPC failed:", e)
			os.Exit(1)
		}
		reqCount++
		if e := dec.Decode(&a); e != nil {
			fmt.Fprintln(os.Stderr, "read from ctrl RPC failed:", e)
			os.Exit(1)
		}
		if a.Code == http.StatusOK {
			okCount++
		} else {
			ngCount++
		}
	}
	ticker.Stop()
	c.Close()
}
