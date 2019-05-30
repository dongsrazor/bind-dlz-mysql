// Package dlzmysql implements a plugin that returns details about the resolving
// querying it.
package dlzmysql

import (
	//"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	//"os"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"

	"github.com/coredns/coredns/plugin"
	//"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

//Dlzmysql 定义
type Dlzmysql struct {
	Next    		plugin.Handler
	DB				*sql.DB
	mysqlAddress	string
	mysqlUser		string
	mysqlPassword	string
	mysqlDB			string
	IPtable 		[]IPrange
}

//从mysql中查询A/AAAA/CNAME记录
func (dlz Dlzmysql) get(domain string, queryType string, view string) (records []string) {
	host, zone := getHostZone(domain)
	sql := "SELECT `host`, `zone`, `view`, `type`, `data`, `ttl` FROM `dns_record` " +
	"WHERE `host`='"+ host +"' AND `zone`='"+ zone +
	"' AND `type`='"+ queryType +"' AND `view`='"+ view +"';"
	rows, err := dlz.DB.Query(sql)

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
		r := strings.Join([]string{domain, queryType, data, ttl}, ":")
		records = append(records, r)
	}
	return
}

//从mysql中查询NS记录
func (dlz Dlzmysql) getNS(domain string, queryType string, view string) (records []string) {
	_, zone := getHostZone(domain)
	host := "@"
	sql := "SELECT `host`, `zone`, `view`, `type`, `data`, `ttl` FROM `dns_record` " +
	"WHERE `host`='"+ host +"' AND `zone`='"+ zone +
	"' AND `type`='"+ queryType +"' AND `view`='"+ view +"';"
	rows, err := dlz.DB.Query(sql)
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
		r := strings.Join([]string{domain, queryType, data, ttl}, ":")
		records = append(records, r)
	}
	return	
}

//从mysql中查询MX记录
func (dlz Dlzmysql) getMX(domain string, queryType string, view string) (records []string) {
	_, zone := getHostZone(domain)
	host := "@"
	sql := "SELECT `host`, `zone`, `view`, `type`, `data`, `mx_priority`, `ttl` FROM `dns_record` " +
	"WHERE `host`='"+ host +"' AND `zone`='"+ zone +
	"' AND `type`='"+ queryType +"' AND `view`='"+ view +"';"
	rows, err := dlz.DB.Query(sql)
	for rows.Next() {
		var host string
		var zone string
		var view string
		var queryType string
		var data string
		var mxPriority string
		var ttl string
		err = rows.Scan(&host, &zone, &view, &queryType, &data, &mxPriority, &ttl)
		if err != nil {
			fmt.Println(err)
		}
		r := strings.Join([]string{domain, queryType, data, mxPriority, ttl}, ":")
		records = append(records, r)
	}
	return	
}

//从mysql中查询SOA记录
func (dlz Dlzmysql) getSOA(domain string, queryType string, view string) (records []string) {
	_, zone := getHostZone(domain)
	host := "@"
	sql := "SELECT `host`, `zone`, `view`, `type`, `data`, `ttl`, `resp_person`, `serial`, `refresh`, `retry`, `expire`, `minimum` FROM `dns_record` " +
	"WHERE `host`='"+ host +"' AND `zone`='"+ zone +
	"' AND `type`='"+ queryType +"' AND `view`='"+ view +"';"
	rows, err := dlz.DB.Query(sql)
	for rows.Next() {
		var host string
		var zone string
		var view string
		var queryType string
		var data string
		var ttl string
		var respPersion string
		var serial string
		var refresh string
		var retry string
		var expire string
		var minimum string
        err = rows.Scan(&host, &zone, &view, &queryType, &data, &ttl, &respPersion, &serial, &refresh, &retry, &expire, &minimum)
        if err != nil {
            fmt.Println(err)
		}
		r := strings.Join([]string{domain, queryType, data, respPersion, ttl, serial, refresh, retry, expire, minimum}, ":")
		records = append(records, r)
    }
	return	
}

//A 记录
func (dlz *Dlzmysql) A(name string, records []string) (answers, extras []dns.RR) {
	for _, a := range records {
		vals := strings.Split(a, ":")
		domain := vals[0]
		queryType :=vals[1]
		data := vals[2]
		ttlString := vals[3]
		val, _ := strconv.ParseUint(ttlString, 10, 32)
		ttl := uint32(val)
		
		var rr dns.RR
		rr = new(dns.A)
		rr.(*dns.A).Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: ttl}
		rr.(*dns.A).A = net.ParseIP(data).To4()
		answers = append(answers, rr)			

	}
	return
}

//AAAA 记录
func (dlz *Dlzmysql) AAAA(name string, records []string) (answers, extras []dns.RR) {
	for _, aaaa := range records {
		vals := strings.Split(aaaa, ":")
		//domain := vals[0]
		//queryType := vals[1]
		data := vals[2]
		ttlString := vals[3]
		
		val, _ := strconv.ParseUint(ttlString, 10, 32)
		ttl := uint32(val)
		
		var rr dns.RR
		rr = new(dns.AAAA)
		rr.(*dns.AAAA).Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA,
			Class: dns.ClassINET, Ttl: ttl}
		rr.(*dns.AAAA).AAAA = net.ParseIP(data)
		answers = append(answers, rr)
	}
	return
}

//CNAME 记录
func (dlz *Dlzmysql) CNAME(name string, records []string) (answers, extras []dns.RR) {
	for _, cname := range records {
		vals := strings.Split(cname, ":")
		//domain := vals[0]
		//queryType := vals[1]
		fqdn := vals[2]
		ttlString := vals[3]
		
		val, _ := strconv.ParseUint(ttlString, 10, 32)
		ttl := uint32(val)
		
		var rr dns.RR
		rr = new(dns.CNAME)
		rr.(*dns.CNAME).Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME,
			Class: dns.ClassINET, Ttl: ttl}
		rr.(*dns.CNAME).Target = fqdn
		answers = append(answers, rr)
	}
	return
}

//NS 记录
func (dlz *Dlzmysql) NS(name string, records []string) (answers, extras []dns.RR) {
	for _, ns := range records {
		vals := strings.Split(ns, ":")
		//domain := vals[0]
		//queryType := vals[1]
		fqdn := vals[2]
		ttlString := vals[3]
		
		val, _ := strconv.ParseUint(ttlString, 10, 32)
		ttl := uint32(val)
		
		var rr dns.RR
		rr = new(dns.NS)
		rr.(*dns.NS).Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeNS,
			Class: dns.ClassINET, Ttl: ttl}
		rr.(*dns.NS).Ns = fqdn
		answers = append(answers, rr)
	}
	return
}

//MX 记录
func (dlz *Dlzmysql) MX(name string, records []string) (answers, extras []dns.RR) {
	for _, mx := range records {
		vals := strings.Split(mx, ":")
		//domain := vals[0]
		//queryType := vals[1]
		fqdn := vals[2]
		mxPriority := vals[3]
		ttlString := vals[4]
		
		val, _ := strconv.ParseUint(ttlString, 10, 32)
		ttl := uint32(val)		
		valPriority, _ := strconv.ParseUint(mxPriority, 10, 16)
		priority := uint16(valPriority)

		rr := new(dns.MX)
		rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeMX,
			Class: dns.ClassINET, Ttl: ttl}
		rr.Mx = fqdn
		rr.Preference = priority
		answers = append(answers, rr)
	}
	return
}

//SOA 记录
func (dlz *Dlzmysql) SOA(name string, records []string) (answers, extras []dns.RR) {
	for _, soa := range records {
		vals := strings.Split(soa, ":")
		//domain := vals[0]
		//queryType := vals[1]
		ns := vals[2]
		mbox := vals[3]
		
		ttlString := vals[4]
		ttlUint, _ := strconv.ParseUint(ttlString, 10, 32)
		ttl := uint32(ttlUint)		

		serialString := vals[5]
		serialUint, _ := strconv.ParseUint(serialString, 10, 32)
		serial := uint32(serialUint)
		
		refreshString := vals[6]
		refreshUint, _ := strconv.ParseUint(refreshString, 10, 32)
		refresh := uint32(refreshUint)
		
		retryString := vals[7]
		retryUint, _ := strconv.ParseUint(retryString, 10, 32)
		retry := uint32(retryUint)
		
		expireString := vals[8]
		expireUint, _ := strconv.ParseUint(expireString, 10, 32)
		expire := uint32(expireUint)

		minimumString := vals[9]
		minimumUint, _ := strconv.ParseUint(minimumString, 10, 32)
		minimum := uint32(minimumUint)

		rr := new(dns.SOA)
		rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSOA,
			Class: dns.ClassINET, Ttl: ttl}
		rr.Ns = ns
		rr.Mbox = mbox
		rr.Serial = serial
		rr.Refresh = refresh
		rr.Retry = retry
		rr.Expire = expire
		rr.Minttl = minimum

		answers = append(answers, rr)
	}
	return
}

func getHostZone(domain string) (host, zone string) {
	vs := strings.Split(domain, ".")
	host = strings.Join(vs[0:len(vs)-3], ".")
	begin := len(vs)-3
	end := len(vs)-1
	zone = strings.Join(vs[begin:end], ".")
	return
}

func roundRobin(in []dns.RR) []dns.RR {
	cname := []dns.RR{}
	address := []dns.RR{}
	mx := []dns.RR{}
	rest := []dns.RR{}
	for _, r := range in {
		switch r.Header().Rrtype {
		case dns.TypeCNAME:
			cname = append(cname, r)
		case dns.TypeA, dns.TypeAAAA:
			address = append(address, r)
		case dns.TypeMX:
			mx = append(mx, r)
		default:
			rest = append(rest, r)
		}
	}

	roundRobinShuffle(address)
	roundRobinShuffle(mx)

	out := append(cname, rest...)
	out = append(out, address...)
	out = append(out, mx...)
	return out
}

func roundRobinShuffle(records []dns.RR) {
	switch l := len(records); l {
	case 0, 1:
		break
	case 2:
		if dns.Id()%2 == 0 {
			records[0], records[1] = records[1], records[0]
		}
	default:
		for j := 0; j < l*(int(dns.Id())%4+1); j++ {
			q := int(dns.Id()) % l
			p := int(dns.Id()) % l
			if q == p {
				p = (p + 1) % l
			}
			records[q], records[p] = records[p], records[q]
		}
	}
}

func (dlz *Dlzmysql) connect() (*sql.DB, error) {
	dsn := dlz.mysqlUser + ":" + dlz.mysqlPassword + "@tcp(" + dlz.mysqlAddress + ")/" + dlz.mysqlDB + "?timeout=1s&readTimeout=1s"
	//dsn := "wanghd:smart@tcp(192.168.16.99:3306)/bind9?timeout=1s&readTimeout=1s"
	fmt.Println(dsn)
	db, err := sql.Open("mysql", dsn)
	db.SetMaxOpenConns(2048)
	db.SetMaxIdleConns(1024)
	return db, err
}