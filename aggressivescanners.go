package greynetanalysis

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"sort"

	"github.com/google/gopacket"
	"gonum.org/v1/gonum/stat"
)

type ScannerProfile struct {
	Dest     map[netip.Addr]int
	Port     map[string]int
	PckCount int
}

type ScannerMap map[netip.Addr]*ScannerProfile

func CreateScannerProfile() ScannerMap {
	return make(map[netip.Addr]*ScannerProfile)
}

func (m ScannerMap) AddScannerProfile(p gopacket.Packet) {
	dstip, dok := netip.AddrFromSlice(p.NetworkLayer().NetworkFlow().Dst().Raw())
	srcip, sok := netip.AddrFromSlice(p.NetworkLayer().NetworkFlow().Src().Raw())

	if dok && sok {
		if p.TransportLayer() != nil {
			dstepoint := p.TransportLayer().TransportFlow().EndpointType().String() + ":" + p.TransportLayer().TransportFlow().Dst().String()
			if _, exist := m[srcip]; !exist {
				m[srcip] = &ScannerProfile{Dest: make(map[netip.Addr]int), Port: make(map[string]int)}
				m[srcip].Dest[dstip] = 1
				m[srcip].Port[dstepoint] = 1
			} else {
				if smap, sexist := m[srcip].Dest[dstip]; !sexist {
					smap = 1
				} else {
					smap++
				}
				if pmap, pexist := m[srcip].Port[dstepoint]; !pexist {
					pmap = 1
				} else {
					pmap++
				}
			}
		} else {
			if _, exist := m[srcip]; !exist {
				m[srcip] = &ScannerProfile{Dest: make(map[netip.Addr]int), Port: make(map[string]int)}
				m[srcip].Dest[dstip] = 1
			} else {
				if smap, sexist := m[srcip].Dest[dstip]; !sexist {
					smap = 1
				} else {
					smap++
				}
			}

		}
	}
	m[srcip].PckCount++
}

func (m ScannerMap) MergeScannerMap(mnew ScannerMap) {
	//merge mnew into m
	for k, v := range mnew {
		if _, exist := m[k]; !exist {
			m[k] = v
		} else {
			m[k].PckCount += v.PckCount
			for dk, dv := range v.Dest {
				if _, dexist := m[k].Dest[dk]; !dexist {
					m[k].Dest[dk] = dv
				} else {
					m[k].Dest[dk] += dv
				}
			}
			for pk, pv := range v.Port {
				if _, pexist := m[k].Port[pk]; !pexist {
					m[k].Port[pk] = pv
				} else {
					m[k].Port[pk] += pv
				}
			}
		}
	}
}

func (m ScannerMap) OutputJSON(fname string) {
	outfile, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	j, err := json.Marshal(m)
	if err != nil {
		log.Println(err)
	} else {
		outfile.Write(j)
		log.Println("Output JSON file: ", fname)
	}
}

func (m ScannerMap) GetAggressiveScannersAD() []netip.Addr {
	//Address dispersion
	var ad []netip.Addr
	theshold := 11000000 * 0.1 / 24 //one hour
	for k, v := range m {
		if len(v.Dest) > int(theshold) {
			ad = append(ad, k)
		}
	}
	return ad
}

func (m ScannerMap) GetAggressiveScannersPV() []netip.Addr {
	//Packet Volume
	var pv []netip.Addr
	var vol []float64
	theshold := 1 - 0.0001
	for _, v := range m {
		vol = append(vol, float64(v.PckCount))
	}
	sort.Float64s(vol)
	th := stat.CDF(theshold, stat.Empirical, vol, nil)
	for k, v := range m {
		if float64(v.PckCount) >= th {
			pv = append(pv, k)
		}
	}
	return pv
}

func (m ScannerMap) GetAggressiveScannersDP() []netip.Addr {
	//Distinct dest ports
	var dp []netip.Addr
	var dport []float64
	theshold := 1 - 0.0001
	for _, v := range m {
		dport = append(dport, float64(len(v.Port)))
	}
	sort.Float64s(dport)
	th := stat.CDF(theshold, stat.Empirical, dport, nil)
	for k, v := range m {
		if float64(len(v.Port)) >= th {
			dp = append(dp, k)
		}
	}
	return dp
}
