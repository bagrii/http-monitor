package main

import (
	"net/http"
	"log"
	"crypto/tls"

	"github.com/bagrii/httpdebugger/proxy"
	"github.com/bagrii/httpdebugger/cert"
	"github.com/google/martian/har"
)

func main() {
	addr := ":8081"
	logger := har.NewLogger()
	listener, err := proxy.NewProxy(addr, logger)
	if err != nil {
		log.Printf("Error while creating proxy: %e", err)
		return
	}
	// certificate should be added to the certificate store (to be trusted).
	rootCert, key, err := cert.LoadRootCertificate("/path/to/rootCA.pem", "/path/to/rootCA-key.pem")
	if err != nil {
		log.Fatal("Cannot load root certificate.")
	}
	http_server := http.Server{
		Addr: ":8080",
		Handler: listener,
	}
	go http_server.ListenAndServe()
	handler := har.NewExportHandler(logger)
	// HAR logs server.
	logServer := http.Server{
		Addr: ":8082",
		Handler: handler,
	}
	go logServer.ListenAndServe()
	server := &http.Server{
		Addr:    addr,
		Handler: listener,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig: &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// TODO: implement caching by server name,
				return cert.GenerateCert(chi.ServerName, rootCert, key)
			},
		},
	}
	err = server.ServeTLS(listener, "", "")

	if err != nil {
		log.Printf("Error starting server: %e\n", err)
	}
}