package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang"
)

var tcpdumpre = regexp.MustCompile(`^(2018-06-(?:19|20) \d\d:\d\d:\d\d).*IP\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\..*\s(?:(A|AAAA)\?)\s(?:a-(\d+)\.4uqu\.party\.)`)
var timelayout = "2006-01-02 15:04:05"

type ASData struct {
	QASN  map[int]int
	an    string
	PSQAS map[int]int
	C     int
	UV6   int
	PT    int
}

type FinalData struct {
	AS   map[int]ASData
	Name map[int]string
}

func main() {
	flag.Parse()

	data := make(map[int]ASData)
	namesneeded := make(map[int]bool)
	asnnames := make(map[int]string)

	ASNfd, _ := os.Open("ASN.list")
	ASNbio := bufio.NewReader(ASNfd)

	for {
		l, _, err := ASNbio.ReadLine()
		if err != nil {
			break
		}

		bits := strings.Split(string(l), ",")
		asn, _ := strconv.ParseInt(bits[0], 10, 64)
		asnnames[int(asn)] = bits[1]
	}

	db, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		fmt.Printf("Unable to open GeoLite2-ASN.mmdb , %s\n", err.Error())
		os.Exit(1)
	}

	bioReader := bufio.NewReader(os.Stdin)
	ScanDoneTime, _ := time.Parse(timelayout, "2018-06-20 13:12:59")

	for {
		line, skip, err := bioReader.ReadLine()
		if skip {
			continue
		}

		if err != nil {
			break
		}

		matches := tcpdumpre.FindAllStringSubmatch(string(line), -1)

		if len(matches) == 0 {
			continue
		}

		timeStamp := matches[0][1]
		inboundIP := matches[0][2]
		qType := matches[0][3]
		queriedASN := matches[0][4]
		queriedASNint, _ := strconv.ParseInt(queriedASN, 10, 64)
		namesneeded[int(queriedASNint)] = true

		entry := data[int(queriedASNint)]
		if entry.an == "" {
			entry.PSQAS = make(map[int]int)
			entry.QASN = make(map[int]int)
			entry.an = "N/A"
		}
		entry.C++

		ResolverASN, err := db.ASN(net.ParseIP(inboundIP))
		if err != nil {
			log.Fatalf("what %s", err.Error())
		}
		namesneeded[int(ResolverASN.AutonomousSystemNumber)] = true

		// 2018-06-19 18:03:07

		// str := "2014-11-12T11:45:26.371Z"
		// log.Println(timeStamp)
		ts, _ := time.Parse(timelayout, timeStamp)
		// fmt.Printf("%v\n", ts.Unix() > ScanDoneTime.Unix())
		if ts.Unix() < ScanDoneTime.Unix() {
			// During Scanning
			entry.QASN[int(ResolverASN.AutonomousSystemNumber)]++
		} else {
			// Post Scanning
			entry.PSQAS[int(ResolverASN.AutonomousSystemNumber)]++
		}

		if qType != "A" {
			entry.UV6++
		}

		entry.PT = isPT(int(queriedASNint))
		data[int(queriedASNint)] = entry

	}

	FD := FinalData{
		AS:   data,
		Name: make(map[int]string),
	}

	for k, v := range namesneeded {
		if v {
			FD.Name[k] = asnnames[k]
		}
	}

	b, _ := json.Marshal(FD)
	fmt.Print(string(b))
}

func isPT(in int) int {
	a := in
	if a == 10013 || a == 10796 || a == 10834 || a == 11081 || a == 11404 || a == 11492 || a == 12208 ||
		a == 12389 || a == 12637 || a == 12880 || a == 13097 || a == 132513 || a == 13287 || a == 132924 ||
		a == 133481 || a == 135607 || a == 13999 || a == 14618 || a == 16509 || a == 16617 || a == 174 ||
		a == 17506 || a == 17931 || a == 17974 || a == 18126 || a == 18260 || a == 18264 || a == 198225 ||
		a == 198357 || a == 19994 || a == 20001 || a == 20368 || a == 209 || a == 23184 || a == 2514 ||
		a == 2519 || a == 2527 || a == 25540 || a == 25660 || a == 264111 || a == 264660 || a == 265210 ||
		a == 26725 || a == 27026 || a == 27357 || a == 28088 || a == 29119 || a == 2914 || a == 29256 ||
		a == 33070 || a == 3549 || a == 36947 || a == 37100 || a == 3949 || a == 395439 || a == 39608 ||
		a == 39615 || a == 41966 || a == 4230 || a == 44061 || a == 45187 || a == 4713 || a == 47427 ||
		a == 49840 || a == 51828 || a == 5617 || a == 58683 || a == 59914 || a == 6128 || a == 6724 || a == 6734 ||
		a == 7018 || a == 7029 || a == 7065 || a == 7668 || a == 7922 || a == 8048 || a == 8452 || a == 855 || a == 9121 {

		return 1
	}
	return 0
}
