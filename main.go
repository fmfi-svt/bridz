// bridz is a stateless OIDC broker.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: bridz config.yaml")
	}

	cfg, err := readConfig(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	broker, err := newBroker(cfg)
	if err != nil {
		log.Fatal(err)
	}

	endpoints := op.Endpoints{
		Authorization: op.NewEndpoint("/authorize"),
		Token:         op.NewEndpoint("/token"),
		Userinfo:      op.NewEndpoint("/userinfo"),
		JwksURI:       op.NewEndpoint("/keys"),
	}

	mux := http.NewServeMux()
	opHandler := op.RegisterServer(broker, endpoints)
	mux.Handle("/authorize", broker.bindStateCookie(opHandler))
	mux.Handle("/", opHandler)
	mux.HandleFunc("/upstream/callback", broker.upstreamCallback)

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("listening on %s", cfg.Listen)
	log.Fatal(server.ListenAndServe())
}
