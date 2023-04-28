package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
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

func main() {
	ctx := context.Background()
	gmio := greynetanalysis.NewGreynetMinioiwthContext(ctx)
	for _, f := range gmio.ListNTpcapsbyDate(time.Date(2023, 03, 31, 0, 0, 0, 0, time.UTC)) {
		fmt.Println(f)
	}
	curipinfo := &IPInfo{}
	//just use latest
	curipinfo.CurDate = time.Now()
	curipinfo.KnownScanner = greynetanalysis.NewKnownScanners()
	curipinfo.KnownScanner.AddSource("knownscanner.yaml", "other")
	log.Println("loading latest data structure")
	curipinfo.Pfx2asn = goiputils.NewIPHandlerbyDate(curipinfo.CurDate)
	curipinfo.Mmgeo = goiputils.NewMaxmindCAIDA(ctx, curipinfo.CurDate, "en")
	curipinfo.Naqgeo = goiputils.NewNetacqCAIDA(ctx, curipinfo.CurDate)
	processmiofile(gmio, curipinfo, "test.pcap.gz")
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
	infochan := make(chan *greynetanalysis.PacketAnnotation, 1000)
	wgchan.Add(1)
	go func() {
		streammetadata(infochan, "test.json.gz")
		wgchan.Done()
	}()
	for {
		data, _, err := pcapreader.ReadPacketData()
		if err == nil {
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			wg.Add(1)
			go func(pkt gopacket.Packet, cnt int) {
				annotation := greynetanalysis.AnnotatePacket(pkt, cnt, ipinfo.Pfx2asn, ipinfo.Mmgeo, ipinfo.Naqgeo, ipinfo.KnownScanner)
				infochan <- annotation
				wg.Done()
			}(pkt, cnt)
			cnt += 1
			if cnt%10000 == 0 {
				log.Println("read", cnt, "packets")
			}
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
