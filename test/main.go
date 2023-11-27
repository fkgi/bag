package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/fkgi/bag"
)

var (
	impi = "999991122223333@ims.mnc99.mcc999.3gppnetwork.org"
	impu = "sip:+9991122223333@ims.mnc99.mcc999.3gppnetwork.org"

	bsfurl    = "http://bsf:8081"
	nafurl    = "http://bsf:8080"
	hssurl    = "http://hss:8080"
	localaddr = "localhost:8080"

	authRetransmit               = 3
	expire         time.Duration = 3

	av = bag.AV{
		RAND: make([]byte, 16),
		AUTN: make([]byte, 16),
		RES:  make([]byte, 16),
		IK:   make([]byte, 16),
		CK:   make([]byte, 16)}
)

const uaPrefix = ""

func main() {
	flag.StringVar(&impi, "i", impi, "IMPI")
	flag.StringVar(&impu, "u", impu, "IMPU")
	flag.StringVar(&bsfurl, "b", bsfurl, "BSF URL")
	flag.StringVar(&nafurl, "n", nafurl, "NAF URL")
	flag.StringVar(&hssurl, "h", hssurl, "HSS URL")
	flag.StringVar(&localaddr, "l", localaddr, "listening address for HTTP proxy")
	flag.Parse()

	log.Println("registering authantication vector for", impi)
	rand.Read(av.RAND)
	log.Printf("RAND = %x\n", av.RAND)
	rand.Read(av.AUTN)
	log.Printf("AUTN = %x\n", av.AUTN)
	rand.Read(av.RES)
	log.Printf("RES  = %x\n", av.RES)
	rand.Read(av.IK)
	log.Printf("IK   = %x\n", av.IK)
	rand.Read(av.CK)
	log.Printf("CK   = %x\n", av.CK)

	if d, e := json.Marshal(av); e != nil {
		log.Fatalln("failed register authentication vector:", e)
	} else if req, e := http.NewRequest(http.MethodPut, hssurl+"/"+impi, bytes.NewBuffer(d)); e != nil {
		log.Fatalln("failed register authentication vector:", e)
	} else if res, e := new(http.Client).Do(req); e != nil {
		log.Fatalln("failed register authentication vector:", e)
	} else if res.StatusCode != http.StatusOK {
		log.Fatalln("failed register authentication vector:", "server returns", res.Status)
	}

	ch := make(chan error)
	log.Println("listening HTTP request on", localaddr)
	go func() {
		ch <- errors.Join(errors.New("HTTP is closed"),
			http.ListenAndServe(localaddr, http.HandlerFunc(gbaClientHandler)))
	}()
	log.Println(<-ch)
}
