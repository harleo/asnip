/*
asnip: ASN target organization IP range attack surface mapping
by https://github.com/harleo/
*/

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
)

type sliceVal []string

func (s sliceVal) String() string {
	var str string
	for _, i := range s {
		str += fmt.Sprintf("%s\n", i)
	}
	return str
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		log.Fatalf("[!] Couldn't create file: %s\n", err.Error())
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func httpRequest(URI string) string {
	response, errGet := http.Get(URI)
	if errGet != nil {
		log.Fatalf("[!] Error sending request: %s\n", errGet.Error())
	}

	responseText, errRead := ioutil.ReadAll(response.Body)
	if errRead != nil {
		log.Fatalf("[!] Error reading response: %s\n", errRead.Error())
	}

	defer response.Body.Close()
	return string(responseText)
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func cidrToIP(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("[!] Failed to convert CIDR to IP: %s\n", err.Error())
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Exclude network and broadcast addresses
	return ips[1 : len(ips)-1]
}

func getIP(ipdomain string) []net.IP {
	ip, err := net.LookupIP(ipdomain)
	if err != nil {
		log.Fatalf("[!] Error looking up domain: %s\n", err.Error())
	}
	return ip
}

func main() {
	orgPtr := flag.String("t", "", "Domain or IP address (Required)")
	printPtr := flag.Bool("p", false, "Print results to console")
	flag.Parse()

	if *orgPtr == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}

	ipAddr := getIP(*orgPtr)[0]

	targetAPIRequest := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=%s", ipAddr)

	// HT specific workaround: split quotes instead of commas in response because easier to parse
	splitTargetResponse := strings.Split(httpRequest(targetAPIRequest), "\"")

	if splitTargetResponse[0] == "API count exceeded - Increase Quota with Membership" {
		fmt.Println("[!] The HackerTarget API limit was reached, exiting...")
		os.Exit(0)
	}

	fmt.Printf("[:] ASN: %s / %s \n", splitTargetResponse[3], splitTargetResponse[7])

	ASAPIRequest := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=AS%s", splitTargetResponse[3])

	// HT specific workaround: split newlines because first line contains AS info
	splitASAPIResponse := strings.Split(httpRequest(ASAPIRequest), "\n")

	cidrs := splitASAPIResponse[1:]
	sort.Strings(cidrs)

	if *printPtr {
		fmt.Print(sliceVal(cidrs))
	}
	fmt.Printf("[:] Writing %d CIDRs to file...\n", len(cidrs))
	writeLines(cidrs, "cidrs.txt")

	var ips []string

	fmt.Println("[:] Converting to IPs...")
	for _, cidr := range cidrs {
		ips = append(ips, cidrToIP(cidr)...)
	}

	for _, ipsValue := range ips {
		if *printPtr {
			fmt.Println(ipsValue)
		}
	}
	fmt.Printf("[:] Writing %d IPs to file...\n", len(ips))
	writeLines(ips, "ips.txt")
}
