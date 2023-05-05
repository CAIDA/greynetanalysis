package greynetanalysis

import (
	"encoding/csv"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/CAIDA/greynoiseapi"

	"github.com/zmap/go-iptree/iptree"
	yaml "gopkg.in/yaml.v3"
)

type KnownTag struct {
	Tag   string
	Valid struct {
		Start time.Time
		End   time.Time
	}
}

type KnownScanners struct {
	IPTag       map[netip.Addr][]KnownTag
	HostnameTag map[string][]KnownTag
	Subnetv4Tag *iptree.IPTree
	//	IPs       map[string][]net.IP
	//	Subnets   map[string][]*net.IPNet
	//	Hostnames map[string][]string
}

func NewKnownScanners() *KnownScanners {
	ks := &KnownScanners{}
	ks.IPTag = make(map[netip.Addr][]KnownTag)
	ks.HostnameTag = make(map[string][]KnownTag)
	ks.Subnetv4Tag = iptree.New()
	//	ks.Subnets = make(map[string][]*net.IPNet)
	//	ks.Hostnames = make(map[string][]string)
	//	ks.IPs = make(map[string][]net.IP)
	return ks
}

func (ks *KnownScanners) AddSource(list, listtype string) {
	listf, err := os.Open(list)
	if err != nil {
		log.Println("load known scanner list error", err)
		return
	}
	defer listf.Close()
	listdata, err := io.ReadAll(listf)
	if err != nil {
		log.Println("read known scanner error", err)
		return
	}
	if listtype == "timed" {
		m := make(map[string][]greynoiseapi.GNQLSimple)
		err := yaml.Unmarshal(listdata, m)
		if err != nil {
			log.Println("error parsing timed scanner", err)
			return
		}
		for currenttag, v := range m {
			for _, data := range v {
				thistag := KnownTag{Tag: currenttag}
				thistag.Valid.Start = data.Valid.Start
				thistag.Valid.End = data.Valid.End
				ipaddr := netip.MustParseAddr(data.IP)
				ks.IPTag[ipaddr] = append(ks.IPTag[ipaddr], thistag)
			}
		}
	} else if listtype == "csv" {
		csvread := csv.NewReader(strings.NewReader(string(listdata)))
		records, err := csvread.ReadAll()
		if err != nil {
			log.Println("failed to parse csv", err)
		}
		//assume format:
		//IP,Tag
		for _, record := range records {
			if len(record) == 2 {
				thistag := KnownTag{Tag: record[1]}
				if ipaddr, err := netip.ParseAddr(record[0]); err == nil {
					//ignore the line that is not IP
					ks.IPTag[ipaddr] = append(ks.IPTag[ipaddr], thistag)
				}
			}
		}
	} else {
		m := make(map[string][]string)
		err := yaml.Unmarshal(listdata, m)
		if err != nil {
			log.Println("error parsing timed scanner", err)
			return
		}
		for tag, addresses := range m {
			for _, address := range addresses {
				thistag := KnownTag{Tag: tag}
				if ipaddr, err := netip.ParseAddr(address); err == nil {
					//this is an IP address
					if ipaddr.Is4() {
						//only support v4 for now
						thistag := KnownTag{Tag: tag}
						ks.IPTag[ipaddr] = append(ks.IPTag[ipaddr], thistag)
					}
				} else {
					if _, err := netip.ParsePrefix(address); err == nil {
						//IP prefix
						ks.Subnetv4Tag.AddByString(address, thistag)
					} else {
						//whatever else treats as hostname
						ks.HostnameTag[address] = append(ks.HostnameTag[address], thistag)
					}
				}
			}
		}
	}

}

func (ks *KnownScanners) Check(ip net.IP, hostname string, seen time.Time) []string {
	detectedtags := make([]string, 0, 0)
	if ip4 := ip.To4(); ip4 != nil {
		ip4addr, _ := netip.AddrFromSlice(ip4)
		if tags, tagexist := ks.IPTag[ip4addr]; tagexist {
			for _, t := range tags {
				//check the date
				if t.Valid.Start.IsZero() || (seen.After(t.Valid.Start) && seen.Before(t.Valid.End)) {
					detectedtags = append(detectedtags, t.Tag)
				}
			}
		}
	}
	//check hostname
	for cname, tags := range ks.HostnameTag {
		if strings.Contains(hostname, cname) {
			for _, tag := range tags {
				detectedtags = append(detectedtags, tag.Tag)
			}
		}
	}
	//check subnet
	if tagval, foundtag, err := ks.Subnetv4Tag.GetByString(ip.String()); err == nil && foundtag {
		t := tagval.(KnownTag)
		detectedtags = append(detectedtags, t.Tag)
	}
	//remove duplicates
	seenstr := make(map[string]bool)
	outputtags := []string{}
	for _, t := range detectedtags {
		if !seenstr[t] {
			outputtags = append(outputtags, t)
			seenstr[t] = true
		}
	}
	return outputtags
}

/*
func LoadKnownScanners(list string) *KnownScanners {
	listf, err := os.Open(list)
	if err != nil {
		log.Println("load known scanner list error", err)
		return nil
	}
	defer listf.Close()
	m := make(map[string][]string)
	data, err := io.ReadAll(listf)
	if err != nil {
		log.Println("read known scanner list error", err)
		return nil
	}
	err = yaml.Unmarshal(data, m)
	if err != nil {
		log.Println("known scanner yaml unmarshal error", err)
		return nil
	}
	ks := &KnownScanners{}
	ks.Subnets = make(map[string][]*net.IPNet)
	ks.Hostnames = make(map[string][]string)
	ks.IPs = make(map[string][]net.IP)
	for k, varr := range m {
		for _, v := range varr {
			//fmt.Println(k, v)
			if ip := net.ParseIP(v); ip != nil {
				//it is an IP address
				if _, sexist := ks.IPs[k]; !sexist {
					ks.IPs[k] = make([]net.IP, 0)
				}
				ks.IPs[k] = append(ks.IPs[k], ip)
			} else {
				//it is a subnet
				_, ipnet, err := net.ParseCIDR(v)
				if err == nil {
					if _, sexist := ks.Subnets[k]; !sexist {
						ks.Subnets[k] = make([]*net.IPNet, 0)
					}
					ks.Subnets[k] = append(ks.Subnets[k], ipnet)
				} else {
					//treat as hostname
					if _, sexist := ks.Hostnames[k]; !sexist {
						ks.Hostnames[k] = make([]string, 0)
					}
					ks.Hostnames[k] = append(ks.Hostnames[k], v)
				}
			}
		}
	}
	return ks
}

func (k *KnownScanners) Check(ip net.IP, hostname string) string {
	if k.IPs != nil {
		for name, cips := range k.IPs {
			for _, cip := range cips {
				if ip.Equal(cip) {
					return name
				}
			}
		}
	}
	if k.Subnets != nil {
		for name, cnets := range k.Subnets {
			for _, cnet := range cnets {
				if cnet.Contains(ip) {
					return name
				}
			}
		}
	}
	if k.Hostnames != nil {
		for name, chosts := range k.Hostnames {
			for _, chost := range chosts {
				if strings.Contains(hostname, chost) {
					return name
				}
			}
		}
	}
	return ""
}*/
