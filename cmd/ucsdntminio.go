package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"greynetanalysis"
	"io"
	"log"
	"sync"
	"time"

	"github.com/CAIDA/goiputils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type IPInfo struct {
	CurDate       time.Time
	Mmgeo, Naqgeo goiputils.IPMetaProvider
	Pfx2asn       goiputils.IPHandler
	KnownScanner  *greynetanalysis.KnownScanners
}

var nworkers int

func main() {
	ctx := context.Background()
	gmio := greynetanalysis.NewGreynetMinioiwthContext(ctx)
	ks := greynetanalysis.NewKnownScanners()
	ks.AddSource("knownscanner.yaml", "other")
	ks.AddSource("mcscanner.yaml", "other")
	ks.AddSource("data/gn.yaml", "timed")
	ks.AddSource("data/alienvault.csv", "csv")
	var startstr, endstr, dnsresolver string
	flag.StringVar(&startstr, "start", "2023-03-27 00:00", "start date")
	flag.StringVar(&endstr, "end", "2023-04-03 00:00", "end date")
	flag.StringVar(&dnsresolver, "dns", "", "dns resolver")
	flag.StringVar(&nworkers, "w", 100000, "number of workers")
	flag.Parse()
	timeformat := "2006-01-02 03:04"
	startts, err := time.Parse(timeformat, startstr)
	if err != nil {
		log.Fatal("date format incorrect")
	}
	endts, err := time.Parse(timeformat, endstr)
	if err != nil {
		log.Fatal("date format incorrect")
	}
	for cdate := startts; cdate.Before(endts); cdate = cdate.AddDate(0, 0, 1) {
		curipinfo := &IPInfo{}
		//just use latest
		curipinfo.CurDate = cdate
		log.Println("loading latest data structure", cdate)
		ipopt := &goiputils.IPHandlerOptions{Timeout: "500ms"}
		if dnsresolver != "" {
			ipopt.DNSResolverLoc = dnsresolver
		}
		ipopt.Date = curipinfo.CurDate
		curipinfo.Pfx2asn = goiputils.NewIPHandlerwithOptions(ipopt)
		//curipinfo.Pfx2asn = goiputils.NewIPHandlerbyDate(curipinfo.CurDate)
		curipinfo.Mmgeo = goiputils.NewMaxmindCAIDA(ctx, curipinfo.CurDate, "en")
		curipinfo.Naqgeo = goiputils.NewNetacqCAIDA(ctx, curipinfo.CurDate)
		curipinfo.KnownScanner = ks

		for _, f := range gmio.ListNTpcapsbyDate(cdate) {
			fmt.Println(f)
			processmiofile(gmio, curipinfo, f)
		}
	}
}

func streammetadata(infochan chan *greynetanalysis.PacketAnnotation, filename string) {
	//	var bjson bytes.Buffer
	log.Println("start streammetadata")
	gmio := greynetanalysis.NewGreynetMinioiwthContext(context.Background())
	r, w := io.Pipe()
	var wgup sync.WaitGroup
	wgup.Add(1)
	go func() {
		up := gmio.PutMetaData(filename, r)
		log.Println(up)
		wgup.Done()
	}()
	gzwrite := gzip.NewWriter(w)
	for info := range infochan {
		//		log.Println(info)
		jinfo, err := json.Marshal(info)
		if err == nil {
			//append a newline
			jinfo = append(jinfo, '\n')
			//log.Printf(string(jinfo))
			_, err := gzwrite.Write(jinfo)
			if err != nil {
				log.Println(err)
			}
		} else {
			log.Println("failed to marshal json")
		}
	}
	log.Println("streammetadata ending")
	/*	err := gzwrite.Flush()
		if err != nil {
			log.Println("flush gwwriter error ", err)
		}
	*/
	err := gzwrite.Close()
	if err != nil {
		log.Println("close gwwriter error ", err)
	}

	err = w.Close()
	if err != nil {
		log.Println("close writer error ", err)
	}
	wgup.Wait()
	err = r.Close()
	if err != nil {
		log.Println("close reader error ", err)
	}
}

func processmiofile(gmio greynetanalysis.GreynetMinio, ipinfo *IPInfo, filepath string) {
	var wg, wgchan sync.WaitGroup
	log.Println("processing file:", filepath)
	pcapgz := gmio.GetObject(filepath)
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
	cnt := 1
	infochan := make(chan *greynetanalysis.PacketAnnotation, 10000)
	wgchan.Add(1)
	go func() {
		jsonname := filepath[:len(filepath)-8] + ".jsonl.gz"
		streammetadata(infochan, jsonname)
		wgchan.Done()
	}()
	packetworker := make(chan bool, nworkers)
	for {
		data, _, err := pcapreader.ReadPacketData()
		if err == nil {
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			packetworker <- true
			wg.Add(1)
			go func(pkt gopacket.Packet, cnt int) {
				annotation := greynetanalysis.AnnotatePacket(pkt, cnt, ipinfo.Pfx2asn, ipinfo.Mmgeo, ipinfo.Naqgeo, ipinfo.KnownScanner)
				infochan <- annotation
				<-packetworker
				wg.Done()
			}(pkt, cnt)
			cnt += 1
			/*			if cnt%10000 == 0 {
						log.Println("read", cnt, "packets")
					}*/
			//			fmt.Println("zmap:", greynetanalysis.IsZmap(pkt), "masscan:", greynetanalysis.IsMasscan(pkt), "mirai:", greynetanalysis.IsMirai(pkt))
		} else {
			break
		}
	}
	wg.Wait()
	log.Println("closing channel")
	close(infochan)
	wgchan.Wait()
	log.Println("writing final bits")
}
