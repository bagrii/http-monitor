package proxy

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/martian/har"
)

var hopByHopHeaders []string = []string{
	http.CanonicalHeaderKey("keep-alive"),
	http.CanonicalHeaderKey("proxy-authenticate"),
	http.CanonicalHeaderKey("proxy-authorization"),
	http.CanonicalHeaderKey("te"),
	http.CanonicalHeaderKey("trailers"),
	http.CanonicalHeaderKey("transfer-encoding"),
}

type Proxy struct {
	net.Listener
	Inbound chan net.Conn
	Logger *har.Logger
	gen *rand.Rand
}

func (p Proxy) Accept() (net.Conn, error) {
	return <- p.Inbound, nil
}

func (p Proxy) WaitInboundConnection() {
	for {
		conn, err := p.Listener.Accept()
		if err == nil {
			p.Inbound <- conn
		}
	}
}

func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "HTTP/1.1 200 Connection established\r\nProxy-Agent: httpdebugger/1.0\r\n\r\n")
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported.", http.StatusServiceUnavailable)
			return
		}
		// prevent from closing inbound connection. 
		inbound, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		// stuff the connection from client to our loop to start TLS handshake in case
		// of HTTPS, otherwise just process request HTTP request.
		p.Inbound <- inbound
	} else {
		p.adjustRequest(r)
		id := p.genID()
		err := p.Logger.RecordRequest(id, r)
		if err != nil {
			log.Printf("Cannot log request due to error: %e", err)
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		err = p.Logger.RecordResponse(id, resp)
		if err != nil {
			log.Printf("Cannot log response due to error: %e", err)
		}
		defer resp.Body.Close()
		p.copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// adjustRequest update the internals of URL when request is over HTTPS
// as this MITM server, the client think this is the original server, so
// the request path is relative to destination server.
func (p Proxy) adjustRequest(r *http.Request) {
	if !r.URL.IsAbs() {
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
	}
	// remove hop-by-hop headers.
	for _, header := range hopByHopHeaders {
		r.Header.Del(header)
	}
}

func (p Proxy) copyHeader(dst, src http.Header) {
	ignore := make(map[string]bool)
	for _, header := range hopByHopHeaders {
		ignore[header] = true
	}
	for _, header := range src["Connection"] {
		ignore[http.CanonicalHeaderKey(header)] = true
	}

    for name, values := range src {
		// do not copy hop-by-hop headers.
		if ignore[name] {
			continue
		}
        for _, v := range values {
            dst.Add(name, v)
        }
    }
}

func (p Proxy) genID() string {
	return strconv.Itoa(p.gen.Int())
}

func NewProxy(addr string, logger *har.Logger) (Proxy, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return Proxy{}, err
	}
	p := Proxy{
		Listener: listener,
		Inbound: make(chan net.Conn),
		Logger: logger,
		gen: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	go p.WaitInboundConnection()

	return p, nil
}