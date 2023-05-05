package main

import (
	"context"
	"encoding/json"
	"fmt"
	"greynetanalysis"
	"log"
	"os"
	"sync"
	"time"

	"github.com/CAIDA/goiputils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	pcapf, err := os.Open("test.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer pcapf.Close()
	pcapreader, err := pcapgo.NewReader(pcapf)
	if err != nil {
		log.Fatal(err)
	}
	var mmgeo, naqgeo goiputils.IPMetaProvider
	var pfx2asn goiputils.IPHandler
	var known *greynetanalysis.KnownScanners
	annotations := make([]*greynetanalysis.PacketSummary, 0, 0)
	ctx := context.Background()
	cnt := 1
	var wg sync.WaitGroup
	starttime := time.Now()
	fmt.Println("start:", starttime)
	for {
		data, ci, err := pcapreader.ReadPacketData()
		if err == nil {
			if cnt == 1 {
				log.Println("initialzing")
				pfx2asn = goiputils.NewIPHandlerbyDate(ci.Timestamp)
				log.Println("completed loading pfx2asn")
				mmgeo = goiputils.NewMaxmindCAIDA(ctx, ci.Timestamp, "en")
				log.Println("completed loading maxmind")
				naqgeo = goiputils.NewNetacqCAIDA(ctx, ci.Timestamp)
				log.Println("completed loading netacq")
				known = greynetanalysis.NewKnownScanners()
				known.AddSource("knownscanner.yaml", "other")
				known.AddSource("mcscanner.yaml", "other")
				known.AddSource("data/gn.yaml", "timed")
				known.AddSource("data/alienvault.csv", "csv")

			}
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			wg.Add(1)
			go func(pkt gopacket.Packet, ci gopacket.CaptureInfo, cnt int) {

				a := greynetanalysis.AnnotatePacketwithSummary(pkt, cnt, pfx2asn, mmgeo, naqgeo, known)
				a.Timestamp = ci.Timestamp
				annotations = append(annotations, a)
				//				fmt.Println(annotation)
				wg.Done()
			}(pkt, ci, cnt)
			cnt += 1
			//			fmt.Println("zmap:", greynetanalysis.IsZmap(pkt), "masscan:", greynetanalysis.IsMasscan(pkt), "mirai:", greynetanalysis.IsMirai(pkt))
		} else {
			break
		}
	}
	wg.Wait()
	endtime := time.Now()
	fmt.Println("annotated", len(annotations))
	fmt.Println("end:", endtime, "duration:", endtime.Sub(starttime))
	jan, _ := json.Marshal(annotations)
	_ = os.WriteFile("pcksum.json", jan, 0644)
}
