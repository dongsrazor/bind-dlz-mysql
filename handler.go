// Package dlzmysql implements a plugin that returns details about the resolving
// querying it.
package dlzmysql

import (
	"context"
	"strings"
	//"fmt"

	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (dlz *Dlzmysql) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
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
	authorities := []dns.RR{}
	extras := []dns.RR{}

	switch qtype {
	case "A":
		//获取NS记录
		//_, zone := getHostZone(domain)
		//zone += "."
		//rs := dlz.getNS(zone, "NS", view)
		//authorities, extras = dlz.NS(zone, rs)
		//A->CNAME 直至找到最终解析
		for {
			rs := dlz.get(domain, "A", view)
			if len(rs) == 0 {
				rs := dlz.get(domain, "CNAME", view)
				if len(rs) == 0 {
					break
				} else if len(rs) == 1 {
					ans, _ := dlz.CNAME(domain, rs)
					answers = append(answers, ans...)
					values := strings.Split(rs[0], ":")
					domain = values[2]
				} else {
					break
				}
			} else {
				ans, _ := dlz.A(domain, rs)
				roundRobinAnswers := roundRobin(ans)	//轮询返回A记录
				answers = append(answers, roundRobinAnswers...)
				break
			}
		}
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
	default:
		break
	}
	
	a.Answer = append(a.Answer, answers...)
	a.Ns = append(a.Ns, authorities...)
	a.Extra = append(a.Extra, extras...)

	w.WriteMsg(a)

	return 0, nil
}

// Name implements the Handler interface.
func (dlz Dlzmysql) Name() string { return "dlzmysql" } 
