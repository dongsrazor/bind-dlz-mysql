package dlzmysql

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

//IPrange IP段
type IPrange struct {
	startip  string
	endip    string
	startint uint32
	endint   uint32
	view     string
	update   int
}

func ipTouint32(ipnr net.IP) uint32 {
	bits := strings.Split(ipnr.String(), ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	var sum uint32
	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)
	return sum
}

func loadIPtable() (iptable []IPrange) {
	inputFile, inputError := os.Open("dlzmysql.iptable.dat")
	if inputError != nil {
		log.Error(inputError)
		os.Exit(1)
	}
	defer inputFile.Close()

	inputReader := bufio.NewReader(inputFile)
	for {
		line, readerError := inputReader.ReadString('\n')
		line = strings.Replace(line, "\n", "", -1)
		if readerError == io.EOF {
			return iptable
		}
		values := strings.Split(line, ",")
		var ipr IPrange
		ipr.startip = values[0]
		ipr.endip = values[1]
		val, _ := strconv.ParseUint(values[2], 10, 32)
		ipr.startint = uint32(val)
		val, _ = strconv.ParseUint(values[3], 10, 32)
		ipr.endint = uint32(val)
		ipr.view = values[4]
		iptable = append(iptable, ipr)
	}

}

func queryIP(iptable []IPrange, ip string) (view string) {
	ipstring := net.ParseIP(ip)
	ipint := ipTouint32(ipstring)
	lid := 0
	hid := len(iptable) - 1
	for {
		mid := (lid + hid) / 2
		startint := iptable[mid].startint
		endint := iptable[mid].endint
		if ipint < startint {
			hid = mid - 1
		} else if ipint > endint {
			lid = mid + 1
		} else {
			view = iptable[mid].view
			return
		}
	}
}
