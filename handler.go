// Package dlzmysql implements a plugin that returns details about the resolving
// querying it.
package dlzmysql

import (
	"context"
	//"fmt"
	//"net"

	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (dlz Dlzmysql) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	//qname := state.Name()
	qtype := state.Type()
	domain := state.QName()
	//fmt.Println(domain, qname, qtype)
	
	a := new(dns.Msg)
	a.SetReply(r)
	a.Authoritative = true
	//a.Authoritative, a.RecursionAvailable, a.Compress = true, false, true

	ip := state.IP()
	view := queryIP(dlz.IPtable, ip)

	answers := []dns.RR{}
	extras := []dns.RR{}

	switch qtype {
	case "A":
		records := dlz.get(domain, qtype, view)
		answers, extras = dlz.A(domain, records)
	case "CNAME":
		records := dlz.get(domain, qtype, view)
		answers, extras = dlz.CNAME(domain, records)
	case "NS":
		records := dlz.getNS(domain, qtype, view)
		answers, extras = dlz.NS(domain, records)
	case "MX":
		records := dlz.getMX(domain, qtype, view)
		answers, extras = dlz.MX(domain, records)
	case "SOA":
		records := dlz.getSOA(domain, qtype, view)
		answers, extras = dlz.SOA(domain, records)						
	//default:
	//	return answers, extras
	}
	
	a.Answer = append(a.Answer, answers...)
	a.Extra = append(a.Extra, extras...)

	w.WriteMsg(a)

	return 0, nil
}

// Name implements the Handler interface.
func (dlz Dlzmysql) Name() string { return "dlzmysql" } 
