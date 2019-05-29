// Package dlzmysql implements a plugin that returns details about the resolving
// querying it.
package dlzmysql

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	//"os"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"
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

var db, err = sql.Open("mysql", "wanghd:smart@tcp(192.168.16.99)/bind9")


// ServeDNS implements the plugin.Handler interface.
func (wh Dlzmysql) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	qname := state.Name()
	qtype := state.Type()
	fmt.Println(qname)
	fmt.Println(qtype)
	a := new(dns.Msg)
	a.SetReply(r)
	a.Authoritative = true

	ip := state.IP()
	domain := state.QName()
	
	queryTypeTest := state.QType()
	if queryTypeTest == dns.TypeA {
		fmt.Println("查询A记录")
	} else if queryTypeTest == dns.TypeCNAME {
		fmt.Println("查询CNAME")
	} else {
		fmt.Println(queryTypeTest)
	}

	view := queryIP(wh.IPtable, ip)
	queryType := "A"

        var rr dns.RR
        a.Answer = []dns.RR{}

	records := getAfromDB(domain, queryType, view)
	for _, value := range records {
		vs := strings.Split(value, ":")
		ip := vs[0]
		recordTTL := vs[1]
		val, _ := strconv.ParseUint(recordTTL, 10, 32)
		ttl := uint32(val)
                rr = new(dns.A)
                rr.(*dns.A).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass(), Ttl: ttl}
                rr.(*dns.A).A = net.ParseIP(ip).To4()
                a.Answer = append(a.Answer, rr)
	}

	w.WriteMsg(a)

	return 0, nil
}

// Name implements the Handler interface.
func (wh Dlzmysql) Name() string { return "dlzmysql" } 

func getHostZone(domain string) (host, zone string) {
	vs := strings.Split(domain, ".")
	//fmt.Println(vs)
	//fmt.Println(len(vs))
	host = strings.Join(vs[0:len(vs)-3], ".")
	begin := len(vs)-3
	end := len(vs)-1
	zone = strings.Join(vs[begin:end], ".")
	return
}

func getAfromDB(domain string, queryType string, view string) ([]string) {
	records := []string{}
        host, zone := getHostZone(domain)
        //queryType := "A"
        sql := "SELECT `host`, `zone`, `view`, `type`, `data`, `ttl` FROM `dns_record` " +
               "WHERE `host`='"+ host +"' AND `zone`='"+ zone +"' AND `type`='"+ queryType +"' AND `view`='"+ view +"';"
        //fmt.Println(sql)
        rows, err := db.Query(sql)
        for rows.Next() {
                var host string
                var zone string
                var view string
                var queryType string
                var data string
                var ttl string
                err = rows.Scan(&host, &zone, &view, &queryType, &data, &ttl)
                if err != nil {
                        fmt.Println(err)
                }
                //fmt.Println(host, zone, view, queryType, data, ttl)
		records = append(records, data + ":" + ttl)

        }
	fmt.Println(records)
	return records
}

func getCNAMEfromDB(domain string, queryType string, view string) ([]string) {
        records := []string{}
        host, zone := getHostZone(domain)
        sql := "SELECT `host`, `zone`, `view`, `type`, `data`, `ttl` FROM `dns_record` " +
               "WHERE `host`='"+ host +"' AND `zone`='"+ zone +"' AND `type`='"+ queryType +"' AND `view`='"+ view +"';"
        //fmt.Println(sql)
        rows, err := db.Query(sql)
        for rows.Next() {
                var host string
                var zone string
                var view string
                var queryType string
                var data string
                var ttl string
                err = rows.Scan(&host, &zone, &view, &queryType, &data, &ttl)
                if err != nil {
                        fmt.Println(err)
                }
                //fmt.Println(host, zone, view, queryType, data, ttl)
                records = append(records, data + ":" + ttl)

        }
        fmt.Println(records)
        return records
}
