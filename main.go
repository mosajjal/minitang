package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// minitang serves the Tang network-bound encryption protocol.
//
// Two run modes:
//
//   - inetd / socket-activated (default): reads one HTTP request from
//     stdin, writes the response to stdout, exits. Pair with systemd
//     Accept=yes, inetd, xinetd, or `socat ... EXEC:minitang ...`.
//     This mode works under both stdgo and TinyGo.
//
//   - standalone (`-listen :8080`): runs a long-lived net/http server.
//     This requires net.Listen, which works with stdgo but NOT with
//     TinyGo (TinyGo's net package needs a netdev driver registered
//     and has no host-syscall backend). Use stdgo for this mode.

var listenAddr = flag.String("listen", "", "if set, run as standalone HTTP server on this addr (e.g. :8080); otherwise run inetd-style on stdin/stdout")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-listen addr] <keydir>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	dir := flag.Arg(0)

	ks, err := loadKeys(dir)
	if err != nil {
		fatal("load keys: " + err.Error())
	}

	if *listenAddr != "" {
		serveHTTP(ks, *listenAddr)
		return
	}
	serveCGI(ks)
}

// serveCGI handles a single request from stdin, response to stdout.
func serveCGI(ks *Keyset) {
	req, err := http.ReadRequest(bufio.NewReader(os.Stdin))
	if err != nil {
		writeStatus(os.Stdout, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	defer req.Body.Close()

	code, ct, body := dispatch(ks, req)
	writeResponse(os.Stdout, code, ct, body)
}

// serveHTTP runs as a long-lived HTTP server. stdgo only.
func serveHTTP(ks *Keyset, addr string) {
	mux := http.NewServeMux()
	handle := func(w http.ResponseWriter, r *http.Request) {
		code, ct, body := dispatch(ks, r)
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(code)
		w.Write(body)
	}
	mux.HandleFunc("/adv", handle)
	mux.HandleFunc("/adv/", handle)
	mux.HandleFunc("/rec/", handle)

	fmt.Fprintf(os.Stderr, "minitang listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fatal(err.Error())
	}
}

// dispatch routes a request and returns (status, content-type, body).
func dispatch(ks *Keyset, req *http.Request) (int, string, []byte) {
	switch {
	case req.Method == http.MethodGet && (req.URL.Path == "/adv" || strings.HasPrefix(req.URL.Path, "/adv/")):
		return handleAdv(ks, req)
	case req.Method == http.MethodPost && strings.HasPrefix(req.URL.Path, "/rec/"):
		return handleRec(ks, req)
	default:
		return http.StatusNotFound, "text/plain", []byte("not found\n")
	}
}

func handleAdv(ks *Keyset, req *http.Request) (int, string, []byte) {
	if len(ks.Sign) == 0 {
		return http.StatusInternalServerError, "text/plain", []byte("no signing keys\n")
	}
	tp := strings.TrimPrefix(req.URL.Path, "/adv")
	tp = strings.TrimPrefix(tp, "/")

	signer := ks.FindSigner(tp)
	if signer == nil {
		return http.StatusNotFound, "text/plain", []byte("unknown signing key\n")
	}

	payload, err := json.Marshal(map[string][]*JWK{"keys": ks.AdvPub})
	if err != nil {
		return http.StatusInternalServerError, "text/plain", []byte(err.Error())
	}
	jws, err := signJWS(payload, signer)
	if err != nil {
		return http.StatusInternalServerError, "text/plain", []byte(err.Error())
	}
	return http.StatusOK, "application/jose+json", jws
}

func handleRec(ks *Keyset, req *http.Request) (int, string, []byte) {
	tp := strings.TrimPrefix(req.URL.Path, "/rec/")
	if tp == "" {
		return http.StatusBadRequest, "text/plain", []byte("thumbprint required\n")
	}
	ct := req.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/jwk+json") {
		return http.StatusUnsupportedMediaType, "text/plain", []byte("expected application/jwk+json\n")
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return http.StatusBadRequest, "text/plain", []byte("read body: " + err.Error())
	}
	var in JWK
	if err := json.Unmarshal(body, &in); err != nil {
		return http.StatusBadRequest, "text/plain", []byte("bad json\n")
	}

	priv := ks.FindExchange(tp)
	if priv == nil {
		return http.StatusNotFound, "text/plain", []byte("key not found\n")
	}
	out, err := recoverKey(priv, &in)
	if err != nil {
		return http.StatusBadRequest, "text/plain", []byte(err.Error())
	}
	resp, err := json.Marshal(out)
	if err != nil {
		return http.StatusInternalServerError, "text/plain", []byte(err.Error())
	}
	return http.StatusOK, "application/jwk+json", resp
}

func writeResponse(w io.Writer, code int, contentType string, body []byte) {
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	fmt.Fprintf(bw, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(bw, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(bw, "Connection: close\r\n\r\n")
	bw.Write(body)
	bw.Flush()
}

func writeStatus(w io.Writer, code int, msg string) {
	writeResponse(w, code, "text/plain", []byte(msg+"\n"))
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
