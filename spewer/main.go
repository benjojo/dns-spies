package main

// ./bin/masscan --packet-trace --offline -p 53 --rate 50 --excludefile exclude.list 0.0.0.0/0 | awk '{print $6}' | ./spewer
import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

var (
	dnsPacketMap map[int][]byte
	dnsmapLock   sync.Mutex
)

func main() {
	addr := flag.String("addr", "185.230.223.69", "IP addr you want to send out on")
	flag.Parse()

	dnsPacketMap = make(map[int][]byte)
	addrt := *addr

	db, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		fmt.Printf("Unable to open GeoLite2-ASN.mmdb , %s\n", err.Error())
		os.Exit(1)
	}

	listener, err := net.ListenPacket("udp4", addrt+":5353")
	if err != nil {
		log.Fatalf("failed to listen on UDP %s", err.Error())
	}

	bior := bufio.NewReader(os.Stdin)
	go ReadRes(listener)
	for {
		ips, _, err := bior.ReadLine()
		if err != nil {
			log.Printf("Read errot!")

			break
		}

		addr, err := net.ResolveUDPAddr("udp", string(ips))
		if err != nil {
			log.Printf("unable to parse %s", string(ips))
			continue
		}

		c, err := db.ASN(addr.IP)
		if err != nil {
			log.Printf("unable to lookup %s", string(addr.IP))
			continue
		}

		listener.WriteTo(getPacketForASN(int(c.AutonomousSystemNumber)), addr)
		// time.Sleep(time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	// listener.WriteTo()
}

func getPacketForASN(asn int) []byte {
	cache := dnsPacketMap[asn]
	if cache == nil || len(cache) == 0 {
		m1 := new(dns.Msg)
		m1.Id = dns.Id()
		m1.RecursionDesired = true
		m1.Question = make([]dns.Question, 1)

		m1.Question[0] = dns.Question{
			Name:   fmt.Sprintf("a-%d.4uqu.party.", asn),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}
		dnspacket, _ := m1.Pack()
		dnsmapLock.Lock()
		dnsPacketMap[asn] = dnspacket
		dnsmapLock.Unlock()
		return dnspacket
	}

	return cache
}

func ReadRes(conn net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		conn.ReadFrom(buf)

		// buf := make([]byte, 1500)
		// n, addr, err := conn.ReadFrom(buf)
		// if err != nil {
		// 	log.Printf("err reading %s", err)
		// 	continue
		// }
		// msg := &dns.Msg{}
		// err = msg.Unpack(buf[:n])

		// if err != nil {
		// 	log.Printf("err parsing %s", err)
		// 	continue
		// }

		// if len(msg.Answer) != 1 {
		// 	continue
		// }

		// fmt.Printf("%d,%s,%s\n", time.Now().Unix(), addr.String(), msg.Answer[0].String())
	}

}
