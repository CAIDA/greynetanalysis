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

	var startstr, endstr, outdir string
	flag.StringVar(&startstr, "start", "2023-03-27 00:00", "start date")
	flag.StringVar(&endstr, "end", "2023-04-03 00:00", "end date")
	flag.StringVar(&outdir, "o", ".", "output directory")
	flag.Parse()
	worker := 10
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
	workerch := make(chan bool, worker)
	for cdate := startts; cdate.Before(endts); cdate = cdate.AddDate(0, 0, 1) {
		dayscmap := greynetanalysis.CreateScannerProfile()
		wg.Add(1)
		go func() {
			dayscmap.AddScannerProfile()
			wg.Done()
		}()
		for _, f := range gmio.ListNTpcapsbyDate(cdate) {
			nameparts := strings.Split(filepath.Base(f), `.`)
			ts, _ := strconv.ParseInt(nameparts[1], 10, 64)
			fts := time.Unix(ts, 0)
			if fts.After(cdate) || fts.Equal(cdate) {
				workerch <- true
				wg.Add(1)
				go func(f string) {
					fmt.Println(f)
					processAHmiofile(gmio, f, dayscmap)
					//dayscmap.MergeScannerMap(hrscmap)
					fmt.Println("completed", f)
					<-workerch
					wg.Done()
				}(f)
			}
		}
		close(dayscmap.ScannerChan)
		wg.Wait()
		dayscmap.OutputJSON(filepath.Join(outdir, cdate.Format("2006-01-02")+".daysc.json"))
		dayscmap.OutputStat(filepath.Join(outdir, cdate.Format("2006-01-02")+".stats.csv"))
		//ad := dayscmap.GetAggressiveScannersAD()
		//printiparrtofile(ad, filepath.Join(outdir, cdate.Format("2006-01-02")+".ad.txt"))
		//pv := dayscmap.GetAggressiveScannersPV()
		//printiparrtofile(pv, filepath.Join(outdir, cdate.Format("2006-01-02")+".pv.txt"))
		//dp := dayscmap.GetAggressiveScannersDP()
		//printiparrtofile(dp, filepath.Join(outdir, cdate.Format("2006-01-02")+".dp.txt"))

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

func processAHmiofile(gmio greynetanalysis.GreynetMinio, fpath string, scmap greynetanalysis.ScannerMap) {
	log.Println("processing file:", fpath)
	pcapgz := gmio.GetObject(fpath)
	//	pbuf := bytes.NewBuffer(pcapgz)
	preader, err := gzip.NewReader(pcapgz)
	if err != nil {
		log.Println(err)
		return
	}
	defer preader.Close()
	pcapreader, err := pcapgo.NewReader(preader)
	if err != nil {
		log.Fatal(err)
	}
	for {
		data, _, err := pcapreader.ReadPacketData()
		if err == nil {
			scmap.ScannerChan <- gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		} else {
			break
		}
	}
	//scmap.OutputJSON(filepath.Join(outdir, filepath.Base(fpath[:len(fpath)-8])+".sc.json"))
	return
}
