package bag

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	respAddr = "localhost:6379"
	respChan chan net.Conn
	buf      *bufio.ReadWriter
)

func init() {
	respChan = make(chan net.Conn, 1)
	respChan <- nil
}

func getCachedAV(id string) (av AV, ttl time.Time, e error) {
	c := <-respChan
	defer func() {
		if e != nil {
			c.Close()
			c = nil
		}
		respChan <- c
	}()

	if c == nil {
		c, e = net.Dial("tcp", respAddr)
		if e != nil {
			return
		}
		buf = bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	}

	_, e = fmt.Fprintf(buf, "*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(id), id)
	if e != nil {
		return
	}
	e = buf.Flush()
	if e != nil {
		return
	}

	line, e := buf.ReadString('\n')
	if e != nil {
		return
	}
	switch line[0] {
	case '_': // Null
		return
	case '$': // Bulk String
		var s int
		s, e = strconv.Atoi(strings.TrimSpace(string(line[1:])))
		if e != nil {
			return
		}
		if s < 0 {
			return
		}

		data := make([]byte, s)
		_, e = buf.Read(data)
		if e != nil {
			return
		}
		_, e = buf.ReadString('\n')
		if e != nil {
			return
		}

		e = av.UnmarshalText(data)
		if e != nil {
			av = AV{}
		}
	default: // Others
		e = errors.New("unexpected result")
		return
	}

	_, e = fmt.Fprintf(buf, "*2\r\n$3\r\nTTL\r\n$%d\r\n%s\r\n", len(id), id)
	if e != nil {
		return
	}
	e = buf.Flush()
	if e != nil {
		return
	}

	line, e = buf.ReadString('\n')
	if e != nil {
		return
	}
	switch line[0] {
	case ':': // Integer
		var s int
		s, e = strconv.Atoi(strings.TrimSpace(string(line[1:])))
		if e != nil || s < 0 {
			return
		}
		ttl = time.Now().UTC().Add(time.Second * time.Duration(s))
	default: // Others
		e = errors.New("unexpected result")
		return
	}
	return
}

func setCachedAV(id string, av AV, ttl time.Time) (e error) {
	c := <-respChan
	defer func() {
		if e != nil {
			c.Close()
			c = nil
		}
		respChan <- c
	}()

	if c == nil {
		c, e = net.Dial("tcp", respAddr)
		if e != nil {
			return
		}
		buf = bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	}

	t := strconv.FormatInt(ttl.Unix(), 10)
	v, _ := av.MarshalText()
	_, e = fmt.Fprintf(buf,
		"*5\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n"+
			"$4\r\nEXAT\r\n$%d\r\n%s\r\n",
		len(id), id, len(v), v, len(t), t)
	if e != nil {
		return
	}
	e = buf.Flush()
	if e != nil {
		return
	}

	line, e := buf.ReadString('\n')
	if e != nil {
		return
	}
	switch line[0] {
	case '$', '+', '-':
		return
	default:
		return
	}
}
