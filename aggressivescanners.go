package greynetanalysis

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"gonum.org/v1/gonum/stat"
)

type ScannerProfile struct {
	Dest     map[netip.Addr]uint8
	Port     map[string]uint8
	PckCount uint32
	DestLock *sync.Mutex
}

type ScannerMap struct {
	Scanner     map[netip.Addr]*ScannerProfile
	ScannerLock *sync.RWMutex
}

func CreateScannerProfile() ScannerMap {
	return ScannerMap{Scanner: make(map[netip.Addr]*ScannerProfile), ScannerLock: &sync.RWMutex{}}

}

func ReadScannerProfile(fname string) ScannerMap {
	var m ScannerMap
	infile, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()
	err = json.NewDecoder(infile).Decode(&m)
	if err != nil {
		log.Fatal(err)
	}
	return m
}

func (m ScannerMap) AddScannerProfile(p gopacket.Packet) {
	dstip, dok := netip.AddrFromSlice(p.NetworkLayer().NetworkFlow().Dst().Raw())
	srcip, sok := netip.AddrFromSlice(p.NetworkLayer().NetworkFlow().Src().Raw())

	if dok && sok {
		if p.TransportLayer() != nil {
			dstepoint := p.TransportLayer().TransportFlow().EndpointType().String() + ":" + p.TransportLayer().TransportFlow().Dst().String()
			m.ScannerLock.Lock()
			if _, exist := m.Scanner[srcip]; !exist {
				m.Scanner[srcip] = &ScannerProfile{Dest: make(map[netip.Addr]uint8), Port: make(map[string]uint8), DestLock: &sync.Mutex{}}
				m.ScannerLock.Unlock()
				m.Scanner[srcip].DestLock.Lock()
				m.Scanner[srcip].Dest[dstip] = 1
				m.Scanner[srcip].Port[dstepoint] = 1
				m.Scanner[srcip].DestLock.Unlock()
			} else {
				m.ScannerLock.Unlock()
				m.Scanner[srcip].DestLock.Lock()
				if _, sexist := m.Scanner[srcip].Dest[dstip]; !sexist {
					m.Scanner[srcip].Dest[dstip] = 1
				}
				if _, pexist := m.Scanner[srcip].Port[dstepoint]; !pexist {
					m.Scanner[srcip].Port[dstepoint] = 1
				}
				m.Scanner[srcip].DestLock.Unlock()
			}
		} else {
			m.ScannerLock.Lock()
			if _, exist := m.Scanner[srcip]; !exist {
				m.Scanner[srcip] = &ScannerProfile{Dest: make(map[netip.Addr]uint8), Port: make(map[string]uint8), DestLock: &sync.Mutex{}}
				m.ScannerLock.Unlock()
				m.Scanner[srcip].DestLock.Lock()
				m.Scanner[srcip].Dest[dstip] = 1
			} else {
				m.ScannerLock.Unlock()
				m.Scanner[srcip].DestLock.Lock()
				if _, sexist := m.Scanner[srcip].Dest[dstip]; !sexist {
					m.Scanner[srcip].Dest[dstip] = 1
				}
			}
			m.Scanner[srcip].DestLock.Unlock()
		}
	}
	atomic.AddUint32(&m.Scanner[srcip].PckCount, 1)
}

func (m ScannerMap) MergeScannerMap(mnew ScannerMap) {
	//merge mnew into m
	for k, v := range mnew.Scanner {
		if _, exist := m.Scanner[k]; !exist {
			m.Scanner[k] = v
		} else {
			m.Scanner[k].PckCount += v.PckCount
			for dk, dv := range v.Dest {
				if _, dexist := m.Scanner[k].Dest[dk]; !dexist {
					m.Scanner[k].Dest[dk] = dv
				}
			}
			for pk, pv := range v.Port {
				if _, pexist := m.Scanner[k].Port[pk]; !pexist {
					m.Scanner[k].Port[pk] = pv
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

func (m ScannerMap) OutputStat(fname string) {
	outfile, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	for k, v := range m.Scanner {
		outfile.WriteString(k.String() + "," + string(len(v.Dest)) + "," + string(len(v.Port)) + "\n")
	}
}

func (m ScannerMap) GetAggressiveScannersAD() []netip.Addr {
	//Address dispersion
	var ad []netip.Addr
	theshold := 11000000 * 0.1 / 24 //one hour
	for k, v := range m.Scanner {
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
	for _, v := range m.Scanner {
		vol = append(vol, float64(v.PckCount))
	}
	sort.Float64s(vol)
	th := stat.CDF(theshold, stat.Empirical, vol, nil)
	for k, v := range m.Scanner {
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
	for _, v := range m.Scanner {
		dport = append(dport, float64(len(v.Port)))
	}
	sort.Float64s(dport)
	th := stat.CDF(theshold, stat.Empirical, dport, nil)
	for k, v := range m.Scanner {
		if float64(len(v.Port)) >= th {
			dp = append(dp, k)
		}
	}
	return dp
}
