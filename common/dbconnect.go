package common

import (
	"encoding/gob"
	"net"
	"time"

	"github.com/fkgi/bag"
)

type query struct {
	impi string
	ch   chan bag.AV
}

var (
	queue    = make(chan query, 1024)
	Log      = func(...any) {}
	interval = time.Second
)

func QueryDB(impi string) bag.AV {
	q := query{
		impi: impi,
		ch:   make(chan bag.AV, 1)}
	queue <- q
	return <-q.ch
}

func ConnectDB(path string) {
	for {
		Log()
		Log("[INFO]", "connecting to DB RPC", path)

		c, e := net.Dial("tcp", path)
		if e != nil {
			Log("[ERR]", "connect to DB RPC failed:", e)
			Log("[INFO]", "wait", interval, "for retry to connect to DB RPC")
			time.Sleep(interval)
			continue
		}
		dec := gob.NewDecoder(c)
		enc := gob.NewEncoder(c)
		ticker := time.NewTicker(interval)

		for {
			var q query
			var av bag.AV

			select {
			case q = <-queue:
			case <-ticker.C:
				q.impi = ""
				q.ch = make(chan bag.AV, 1)
			}

			if e = enc.Encode(q.impi); e != nil {
				Log()
				Log("[ERR]", "read from DB RPC failed:", e)
				q.ch <- bag.AV{}
				break
			}
			if e = dec.Decode(&av); e != nil {
				Log()
				Log("[ERR]", "write to DB RPC failed:", e)
				q.ch <- bag.AV{}
				break
			}

			q.ch <- av
		}
		ticker.Stop()
		c.Close()
	}
}
