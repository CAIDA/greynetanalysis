package greynetanalysis

import (
	"io"
	"log"
	"net"
	"os"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

type KnownScanners struct {
	IPs       map[string][]net.IP
	Subnets   map[string][]*net.IPNet
	Hostnames map[string][]string
}

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
}
