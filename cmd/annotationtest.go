package main

import (
	"context"
	"fmt"
	"greynetanalysis"
	"log"
	"os"
	"sync"

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
	var knownscan *greynetanalysis.KnownScanners
	ctx := context.Background()
	cnt := 1
	var wg sync.WaitGroup
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
				knownscan = greynetanalysis.LoadKnownScanners("knownscanner.yaml")
			}
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			wg.Add(1)
			go func(pkt gopacket.Packet, cnt int) {
				annotation := greynetanalysis.AnnotatePacket(pkt, cnt, pfx2asn, mmgeo, naqgeo, knownscan)
				fmt.Println(annotation)
				wg.Done()
			}(pkt, cnt)
			cnt += 1
			//			fmt.Println("zmap:", greynetanalysis.IsZmap(pkt), "masscan:", greynetanalysis.IsMasscan(pkt), "mirai:", greynetanalysis.IsMirai(pkt))
		} else {
			break
		}
	}
	wg.Wait()
}
