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

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
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
	savePtr := flag.Bool("s", false, "Save CIDRs and IPs to text files")
	printPtr := flag.Bool("p", false, "Print results to console")
	flag.Parse()

	if *orgPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	ipAddr := getIP(*orgPtr)[0]

	targetAPIRequest := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=%s", ipAddr)

	// HT specific workaround: split quotes instead of commas in response because easier to parse
	splitTargetResponse := strings.Split(httpRequest(targetAPIRequest), "\"")

	// TODO: Implement error when API rate limit is reached

	fmt.Printf("ASN: %s / %s \n", splitTargetResponse[3], splitTargetResponse[7])

	ASAPIRequest := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=AS%s", splitTargetResponse[3])

	// HT specific workaround: split newlines because first line contains AS info
	splitASAPIResponse := strings.Split(httpRequest(ASAPIRequest), "\n")

	cidrs := splitASAPIResponse[1:]
	sort.Strings(cidrs)

	var cidrList []string
	var ipList []string

	for _, cidr := range cidrs {
		cidrList = append(cidrs)

		if *printPtr {
			fmt.Println(cidr)
		}
	}

	for _, cidr := range cidrs {
		ips := cidrToIP(cidr)

		for _, ipsl := range ips {
			ipList = append(ips)

			if *printPtr {
				fmt.Println(ipsl)
			}
		}
	}

	if *savePtr {
		writeLines(ipList, "./ips.txt")
		writeLines(cidrList, "./cidrs.txt")
	}
}
