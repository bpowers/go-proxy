package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const (
	usage = `Usage: %s [OPTION...]
Envoy-like proxy in Go.

Options:
`
)

var (
	// listener + mTLS
	addr   string
	cacert string
	cert   string
	key    string

	// for debugging
	memProfile string
	cpuProfile string
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&addr, "addr", "",
		"Address to listen on")
	flag.StringVar(&cacert, "cacert", "",
		"certificate authority for peer validation")
	flag.StringVar(&cert, "cert", "",
		"public key certificate")
	flag.StringVar(&key, "key", "",
		"private key")
	flag.StringVar(&memProfile, "memprofile", "",
		"write memory profile to this file")
	flag.StringVar(&cpuProfile, "cpuprofile", "",
		"write cpu profile to this file")

	flag.Parse()
}

func main() {
	if addr == "" {
		log.Fatalf("ERROR: expected address to listen on.\n")
	}
	if key == "" || cert == "" || cacert == "" {
		log.Fatalf("ERROR: expected -cacert, -cert, and -key args")
	}

	prof, err := NewProf(memProfile, cpuProfile)
	if err != nil {
		log.Fatal(err)
	}
	// if -memprof or -cpuprof haven't been set on the command
	// line, these are nops
	prof.Start()
	defer prof.Stop()

	certPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("LoadX509KeyPair(%q, %q): %s", cert, key, err)
		return
	}
	_ = certPair

	caCert, err := ioutil.ReadFile(cacert)
	if err != nil {
		log.Fatalf("ReadFile(%q): %s", cacert, err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		// Certificates: []tls.Certificate{certPair},

		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,

		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,

		// NextProtos: []string{"h2"},

		MinVersion: tls.VersionTLS12,

		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			// tls.X25519,
		},
	}
	tlsConfig.BuildNameToCertificate()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte("hello, peer.\n"))
	})

	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("listening on %s", addr)

	if err := server.ListenAndServeTLS(cert, key); err != nil {
		log.Fatalf("ListenAndServeTLS: %s", err)
	}

	// inner, err := net.Listen("tcp", addr)

	// listener := tls.NewListener(inner, tlsConfig)
	// if err != nil {
	// 	log.Fatalf("NewListener: %s", err)
	// }
	// defer listener.Close()

	// for {
	// 	conn, err := listener.Accept()
	// 	if err != nil {
	// 		log.Println("Accept: %s", err)
	// 		continue
	// 	}
	// 	log.Printf("accepted connection")
	// 	conn.Close()
	// }
}
