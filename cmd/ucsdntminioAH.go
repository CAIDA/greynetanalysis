package main

import (
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"greynetanalysis"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	ctx := context.Background()
	gmio := greynetanalysis.NewGreynetMinioiwthContext(ctx)

	var startstr, endstr, dnsresolver string
	flag.StringVar(&startstr, "start", "2023-03-27 00:00", "start date")
	flag.StringVar(&endstr, "end", "2023-04-03 00:00", "end date")
	flag.Parse()
	timeformat := "2006-01-02 15:04"
	startts, err := time.Parse(timeformat, startstr)
	if err != nil {
		log.Fatal("date format incorrect")
	}
	endts, err := time.Parse(timeformat, endstr)
	if err != nil {
		log.Fatal("date format incorrect")
	}
	var wg sync.WaitGroup
	for cdate := startts; cdate.Before(endts); cdate = cdate.AddDate(0, 0, 1) {
		dayscmap := greynetanalysis.CreateScannerProfile()
		for _, f := range gmio.ListNTpcapsbyDate(cdate) {
			name := filepath.Base(f)
			nameparts := strings.Split(name, `.`)
			ts, _ := strconv.ParseInt(nameparts[1], 10, 64)
			fts := time.Unix(ts, 0)
			if fts.After(cdate) || fts.Equal(cdate) {
				wg.Add(1)
				go func(f string) {
					fmt.Println(f)
					hrscmap := processAHmiofile(gmio, f)
					dayscmap.MergeScannerMap(hrscmap)
					wg.Done()
				}(f)
			}
		}
		wg.Wait()
		ad := dayscmap.GetAggressiveScannersAD()
		printiparrtofile(ad, cdate.Format("2006-01-02")+".ad.txt")
		pv := dayscmap.GetAggressiveScannersPV()
		printiparrtofile(pv, cdate.Format("2006-01-02")+".pv.txt")
		dp := dayscmap.GetAggressiveScannersDP()
		printiparrtofile(dp, cdate.Format("2006-01-02")+".dp.txt")

	}
}

func printiparrtofile(ad []netip.Addr, fname string) {
	outfile, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	for _, v := range ad {
		outfile.WriteString(v.String() + "\n")
	}
}

func processAHmiofile(gmio greynetanalysis.GreynetMinio, filepath string) greynetanalysis.ScannerMap {
	log.Println("processing file:", filepath)
	pcapgz := gmio.GetObject(filepath)
	//	pbuf := bytes.NewBuffer(pcapgz)
	preader, err := gzip.NewReader(pcapgz)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer preader.Close()
	pcapreader, err := pcapgo.NewReader(preader)
	if err != nil {
		log.Fatal(err)
	}
	scmap := greynetanalysis.CreateScannerProfile()
	for {
		data, _, err := pcapreader.ReadPacketData()
		if err == nil {
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			scmap.AddScannerProfile(pkt)
		} else {
			break
		}
	}
	scmap.OutputJSON(filepath[:len(filepath)-8] + ".sc.json")
	return scmap
}
