// Package dlzmysql implements a plugin that returns details about the resolving
// querying it.
package dlzmysql

import (
	"context"
	"strings"
	"time"
	"strconv"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (dlz *Dlzmysql) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	start := time.Now()	
	state := request.Request{W: w, Req: r}
	queryType := state.Type()
	domain := state.QName()
	ip := state.IP()

	a := new(dns.Msg)
	a.SetReply(r)
	a.Authoritative, a.RecursionAvailable, a.Compress = true, false, false
	answers := []dns.RR{}
	authorities := []dns.RR{}
	extras := []dns.RR{}

	//获取bind-dlz-mysql定义的用户view
	queryView := queryIP(dlz.IPtable, ip)

	switch queryType {
	case "A":
		chain := []string{}
		//A->CNAME...->A 直至找到最终解析A记录
		for {
			rs := dlz.get(domain, "A", queryView)
			if len(rs) == 0 {
				rs := dlz.get(domain, "CNAME", queryView)
				if len(rs) == 0 {
					break
				} else if len(rs) == 1 {
					ans, _ := dlz.CNAME(domain, rs)
					answers = append(answers, ans...)
					values := strings.Split(rs[0], "#")
					domain = values[2]
					chain = append(chain, domain)
				} else {
					break
				}
			} else {
				ans, _ := dlz.A(domain, rs)
				roundRobinAnswers := roundRobin(ans)	//轮询返回A记录
				answers = append(answers, roundRobinAnswers...)
				chain = append(chain, domain)
				break
			}
		}
		//多层CNAME：返回最后一个CNAME的权威NS记录
		number := len(chain)
		if number > 0 {
			//获取NS记录
			_, zone := getHostZone(chain[number-1])
			zone += "."
			rs := dlz.getNS(zone, "NS", queryView)
			ans, _ := dlz.NS(zone, rs)
			authorities = roundRobin(ans)	//轮询返回NS记录
		}
	case "AAAA":
		chain := []string{}
		//AAAA->CNAME...->AAAA直至找到最终解析AAAA记录
		for {
			rs := dlz.get(domain, "AAAA", queryView)
			if len(rs) == 0 {
				rs := dlz.get(domain, "CNAME", queryView)
				if len(rs) == 0 {
					break
				} else if len(rs) == 1 {
					ans, _ := dlz.CNAME(domain, rs)
					answers = append(answers, ans...)
					values := strings.Split(rs[0], "#")
					domain = values[2]
					chain = append(chain, domain)
				} else {
					break
				}
			} else {
				ans, _ := dlz.AAAA(domain, rs)
				roundRobinAnswers := roundRobin(ans)	//轮询返回AAAA记录
				answers = append(answers, roundRobinAnswers...)
				chain = append(chain, domain)
				break
			}
		}
		//多层CNAME：返回最后一个CNAME的权威NS记录
		number := len(chain)
		if number > 0 {
			//获取NS记录
			_, zone := getHostZone(chain[number-1])
			zone += "."
			rs := dlz.getNS(zone, "NS", queryView)
			ans, _ := dlz.NS(zone, rs)
			authorities = roundRobin(ans)	//轮询返回NS记录
		}
	case "CNAME":
		//获取NS记录
		_, zone := getHostZone(domain)
		zone += "."
		rs := dlz.getNS(zone, "NS", queryView)
		ans, _ := dlz.NS(zone, rs)
		authorities = roundRobin(ans)	//轮询返回NS记录
		records := dlz.get(domain, queryType, queryView)
		answers, extras = dlz.CNAME(domain, records)
	case "NS":
		records := dlz.getNS(domain, queryType, queryView)
		ans, _ := dlz.NS(domain, records)
		answers = roundRobin(ans)	//轮询返回NS记录
		
		//send the IP address (glue) along with NS records.
		for _, rr := range answers {
			fqdn := rr.(*dns.NS).Ns
			rs := dlz.get(fqdn, "A", queryView)
			ans, _ := dlz.A(fqdn, rs)
			extras = append(extras, ans...)
		}
	case "MX":
		//获取NS记录
		_, zone := getHostZone(domain)
		zone += "."
		rs := dlz.getNS(zone, "NS", queryView)
		ans, _ := dlz.NS(zone, rs)
		authorities = roundRobin(ans)	//轮询返回NS记录
		//MX
		records := dlz.getMX(domain, queryType, queryView)
		answers, extras = dlz.MX(domain, records)
	case "SOA":
		//获取NS记录
		_, zone := getHostZone(domain)
		zone += "."
		rs := dlz.getNS(zone, "NS", queryView)
		ans, _ := dlz.NS(zone, rs)
		authorities = roundRobin(ans)	//轮询返回NS记录
		//SOA
		records := dlz.getSOA(domain, queryType, queryView)
		answers, extras = dlz.SOA(domain, records)						
	default:
		break
	}
	
	a.Answer = append(a.Answer, answers...)
	a.Ns = append(a.Ns, authorities...)
	a.Extra = append(a.Extra, extras...)
	w.WriteMsg(a)

	//打印日志
	if dlz.querylog {
		// {type}: qtype of the request
		// {name}: qname of the request
		// {class}: qclass of the request
		// {proto}: protocol used (tcp or udp)
		// {remote}: client’s IP address, for IPv6 addresses these are enclosed in brackets: [::1]
		// {local}: server’s IP address, for IPv6 addresses these are enclosed in brackets: [::1]
		// {size}: request size in bytes
		// {port}: client’s port
		// {duration}: response duration
		// {rcode}: response RCODE
		// {rsize}: raw (uncompressed), response size (a client may receive a smaller response)
		// {>rflags}: response flags, each set flag will be displayed, e.g. “aa, tc”. This includes the qr bit as well
		// {>bufsize}: the EDNS0 buffer size advertised in the query
		// {>do}: is the EDNS0 DO (DNSSEC OK) bit set in the query
		// {>id}: query ID
		// {>opcode}: query OPCODE
		// {common}: the default Common Log Format.
		// {combined}: the Common Log Format with the query opcode.
		// {/LABEL}: any metadata label is accepted as a place holder if it is enclosed between {/ and }, the place holder will be replaced by the corresponding metadata value or the default value - if label is not defined. See the metadata plugin for more information.
		// The default Common Log Format is:
		// `{remote}:{port} - {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}`
		port := state.Port()
		queryClient := strings.Join([]string{ip, port}, ":")
		queryID := strconv.FormatUint(uint64(a.Id), 10)
		queryType := state.Type()
		queryClass := state.Class()
		queryName := state.Name()
		queryProto := state.Proto()
		querySize := strconv.Itoa(state.Len())
		queryDO := strconv.FormatBool(state.Do())
		queryBufsize := strconv.Itoa(state.Size())
		respRcode := dns.RcodeToString[a.Rcode]
		respRflags := ""
		if a.Response {
			respRflags += "qr,"
		}
		if a.Authoritative {
			respRflags += "aa,"
		}
		if a.Truncated {
			respRflags += "tc,"
		}
		if a.RecursionDesired {
			respRflags += "rd,"
		}
		if a.RecursionAvailable {
			respRflags += "ra,"
		}
		if a.Zero {
			respRflags += "z,"
		}
		if a.AuthenticatedData {
			respRflags += "ad,"
		}
		if a.CheckingDisabled {
			respRflags += "cd,"
		}
		respRflags = strings.TrimRight(respRflags, ",")
		respRsize := strconv.Itoa(a.Len())
		respDuration := strconv.FormatFloat(time.Since(start).Seconds(), 'f', -1, 64) + "s"
		
		msg := strings.Join([]string{queryClient, queryView, queryID, queryType, queryClass, queryName,
			queryProto, querySize, queryDO, queryBufsize,
			respRcode, respRflags, respRsize, respDuration}, " ")
		log.Info(msg)
	}
	
	return 0, nil
}

// Name implements the Handler interface.
func (dlz Dlzmysql) Name() string { return "dlzmysql" } 
