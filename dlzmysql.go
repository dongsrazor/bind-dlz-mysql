// Package Dlzmysql implements a plugin that returns details about the resolving
// querying it.
package dlzmysql

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Dlzmysql is a plugin that returns your IP address, port and the protocol used for connecting
// to CoreDNS.
type Dlzmysql struct {
	Next    plugin.Handler
	IPtable []IPrange
}

// ServeDNS implements the plugin.Handler interface.
func (wh Dlzmysql) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	a := new(dns.Msg)
	a.SetReply(r)
	a.Authoritative = true

	ip := state.IP()

	result := queryIP(wh.IPtable, ip)
	fmt.Println(result)
	var rr dns.RR

	switch state.Family() {
	case 1:
		rr = new(dns.A)
		rr.(*dns.A).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass()}
		rr.(*dns.A).A = net.ParseIP(ip).To4()
		rr.(*dns.A).A = net.ParseIP("8.8.88.88").To4()
	case 2:
		rr = new(dns.AAAA)
		rr.(*dns.AAAA).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: state.QClass()}
		rr.(*dns.AAAA).AAAA = net.ParseIP(ip)
	}

	srv := new(dns.SRV)
	srv.Hdr = dns.RR_Header{Name: "_" + state.Proto() + "." + state.QName(), Rrtype: dns.TypeSRV, Class: state.QClass()}
	if state.QName() == "." {
		srv.Hdr.Name = "_" + state.Proto() + state.QName()
	}
	port, _ := strconv.Atoi(state.Port())
	srv.Port = uint16(port)
	srv.Target = "."

	a.Extra = []dns.RR{rr, srv}

	w.WriteMsg(a)

	return 0, nil
}

// Name implements the Handler interface.
func (wh Dlzmysql) Name() string { return "dlzmysql" }
