package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/fkgi/bag"
)

func apiHandler(w http.ResponseWriter, r *http.Request) {
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 2 {
		w.WriteHeader(http.StatusNotFound)
		log.Println("prov fail:", "invalid path:", r.URL.Path)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if av, ok := avs[p[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			log.Println("prov fail:", "getting unknown IMPI:", p[1])
		} else if data, e := json.Marshal(av); e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println("prov fail:", "unable to marshal getting data:", e)
		} else {
			w.Header().Add("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			log.Println("prov success:", "get IMPI", p[1])
		}
	case http.MethodPut:
		data, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		var av bag.AV
		if e := json.Unmarshal(data, &av); e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println("prov fail:", "adding invalid data:", e)
		} else if data, e = json.Marshal(av); e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println("prov fail:", "unable to marshal adding data:", e)
		} else {
			avs[p[1]] = av
			w.Header().Add("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			log.Println("prov success:", "add IMPI", p[1], "with AV", av)
		}
	case http.MethodDelete:
		if _, ok := avs[p[1]]; !ok {
			w.WriteHeader(http.StatusNotFound)
			log.Println("prov fail:", "deleting unknown IMPI:", p[1])
		} else {
			delete(avs, p[1])
			w.WriteHeader(http.StatusNoContent)
			log.Println("prov success:", "delete IMPI", p[1])
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		log.Println("prov fail:", "unallowed method:", r.Method)
	}
}
