package common

import (
	"encoding/gob"
	"net"
	"time"

	"github.com/fkgi/bag"
)

type DBQuery struct {
	IMPI string
	Ch   chan bag.AV
}

var (
	Queue    = make(chan DBQuery, 1024)
	Log      = func(...any) {}
	interval = time.Second
)

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
		var query DBQuery
		var av bag.AV

		for {

			select {
			case query = <-Queue:
			case <-ticker.C:
				query.IMPI = ""
				query.Ch = make(chan bag.AV, 1)
			}

			if e = enc.Encode(query.IMPI); e != nil {
				Log()
				Log("[ERR]", "read from DB RPC failed:", e)
				query.Ch <- bag.AV{}
				break
			}
			if e = dec.Decode(&av); e != nil {
				Log()
				Log("[ERR]", "write to DB RPC failed:", e)
				query.Ch <- bag.AV{}
				break
			}

			query.Ch <- av
		}
		ticker.Stop()
		c.Close()
	}
}
