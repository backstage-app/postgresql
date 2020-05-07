package postgresql

import (
	"errors"
	"github.com/golang-collections/collections/stack"
	"io"
	"log"
	"net"
	"time"
)

type state struct {
	bind     *bindMessage
	parse    *parseMessage
	error    *errorMessage
	complete *commandCompleteMessage
}

type QueryWriter interface {
	Write(q *Query)
}

type Query struct {
	Type         string
	Query        string
	Error        string
	Time         time.Time
	RowsAffected uint
}

// Proxy ...
type Proxy struct {
	connId uint32
	source string
	target string
	writer QueryWriter
	conns  map[uint32]*stack.Stack
}

// NewProxy creates new instance of Proxy
func NewProxy(w QueryWriter) *Proxy {
	return &Proxy{writer: w}
}

func (p *Proxy) From(source string) *Proxy {
	p.source = source
	return p
}

func (p *Proxy) To(target string) *Proxy {
	p.target = target
	return p
}

// Run runs Proxy server on specified port and handles each incoming
// tcp connection in separate goroutine.
func (p *Proxy) Run() error {
	if len(p.source) == 0 || len(p.target) == 0 {
		return errors.New("postgresql.Proxy.Run: source or target missing")
	}

	go func() {
		listener, err := net.Listen("tcp", p.source)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if err := listener.Close(); err != nil {
				log.Println(err)
			}
		}()

		for {
			client, err := listener.Accept()
			if err != nil {
				log.Print(err.Error())
			}

			go p.handleConnection(client)
		}
	}()
	return nil
}

// handleConnection makes connection to target host per each incoming tcp connection
// and forwards all traffic from source to target.
func (p *Proxy) handleConnection(in io.ReadWriteCloser) {
	defer func() {
		if err := in.Close(); err != nil {
			log.Println(err)
		}
	}()

	out, err := net.Dial("tcp", p.target)
	if err != nil {
		log.Print(err)
		return
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Println(err)
		}
	}()

	err = p.proxyTraffic(in, out)
	if err != nil {
		log.Println(err)
	}
}

// proxyTraffic ...
func (p *Proxy) proxyTraffic(client, server io.ReadWriteCloser) error {
	p.connId++

	if _, ok := p.conns[p.connId]; !ok {
		p.conns = make(map[uint32]*stack.Stack)
		p.conns[p.connId] = stack.New()
	}

	requestCollector := &collector{p, originFrontend, packetBuilder{}}
	responseCollector := &collector{p, originBackend, packetBuilder{}}

	// Copy bytes from client to server
	go func() {
		if _, err := io.Copy(io.MultiWriter(server, requestCollector), client); err != nil {
			log.Println(err)
		}
	}()

	// Copy bytes from server to client
	if _, err := io.Copy(io.MultiWriter(client, responseCollector), server); err != nil {
		log.Println(err)
	}

	return nil
}

// collector ...
type collector struct {
	proxy   *Proxy
	origin  byte
	builder packetBuilder
}

func (c *collector) Write(p []byte) (n int, err error) {
	packet, err := c.builder.append(p, c.origin)
	if err != nil {
		println(err)
	}
	if packet != nil {
		for _, message := range packet.messages() {
			switch m := message.(type) {
			case *parseMessage:
				c.proxy.conns[c.proxy.connId].Push(&state{
					bind:     nil,
					parse:    m,
					error:    nil,
					complete: nil,
				})
			case *bindMessage:
				state := c.proxy.conns[c.proxy.connId].Peek().(state)
				state.bind = m
			case *errorMessage:
				state := c.proxy.conns[c.proxy.connId].Peek().(state)
				state.error = m
			case *commandCompleteMessage:
				state := c.proxy.conns[c.proxy.connId].Pop().(state)
				state.complete = m
				c.proxy.writer.Write(&Query{Query: state.parse.query})
			}
		}
	}
	return len(p), nil
}
