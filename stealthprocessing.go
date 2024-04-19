package greynetanalysis

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/CAIDA/goiputils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type ProbeDetails struct {
	ProbeIP   string
	ProbeTime time.Time
	Ttl       uint8
}

type OnlineMap struct {
	Hostmap map[string]map[string][]*ProbeDetails
	Lock    *sync.RWMutex
}

func Processpcap_annotation(pcapgzfile string) {

	pcapf, err := os.Open(pcapgzfile)
	if err != nil {
		log.Fatal(err)
	}
	defer pcapf.Close()
	preader, err := gzip.NewReader(pcapf)
	if err != nil {
		log.Fatal(err)
	}
	defer preader.Close()
	pcapreader, err := pcapgo.NewReader(preader)
	if err != nil {
		log.Fatal(err)
	}
	var mmgeo, naqgeo goiputils.IPMetaProvider
	var pfx2asn goiputils.IPHandler
	var known *KnownScanners
	annotations := make([]*PacketAnnotation, 0, 0)
	ctx := context.Background()
	cnt := 1
	//	var wg sync.WaitGroup
	for {
		data, ci, err := pcapreader.ZeroCopyReadPacketData()
		if err == nil {
			if cnt == 1 {
				log.Println("initialzing")
				pfx2asn = goiputils.NewIPHandlerbyDate(ci.Timestamp)
				log.Println("completed loading pfx2asn")
				mmgeo = goiputils.NewMaxmindCAIDA(ctx, ci.Timestamp, "en")
				log.Println("completed loading maxmind")
				naqgeo = goiputils.NewNetacqCAIDA(ctx, ci.Timestamp)
				log.Println("completed loading netacq")
				known = NewKnownScanners()
				//known.AddSource("knownscanner.yaml", "other")
				//known.AddSource("mcscanner.yaml", "other")
				//known.AddSource("data/gn.yaml", "timed")
				//known.AddSource("data/alienvault.csv", "csv")

			}
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			//			wg.Add(1)
			//			go func(pkt gopacket.Packet, cnt int) {
			annotations = append(annotations, AnnotatePacket(pkt, cnt, pfx2asn, mmgeo, naqgeo, known))
			//				fmt.Println(annotation)
			//				wg.Done()
			//			}(pkt, cnt)
			cnt += 1
			//			fmt.Println("zmap:", greynetanalysis.IsZmap(pkt), "masscan:", greynetanalysis.IsMasscan(pkt), "mirai:", greynetanalysis.IsMirai(pkt))
		} else {
			break
		}
	}
	annotationfilename := pcapgzfile[:len(pcapgzfile)-8] + ".json.gz"
	//	wg.Wait()
	afile, err := os.Create(annotationfilename)
	if err != nil {
		log.Fatal(err)
	}
	defer afile.Close()
	jinfo, err := json.Marshal(annotations)
	if err != nil {
		log.Println("json marshal error", pcapgzfile, err)
	}
	gzwrite := gzip.NewWriter(afile)
	_, _ = gzwrite.Write(jinfo)
	gzwrite.Flush()
	gzwrite.Close()
}

func Processpcap_onlinemap(pcapgzfile string, onlinemap OnlineMap) {

	pcapf, err := os.Open(pcapgzfile)
	if err != nil {
		log.Fatal(err)
	}
	defer pcapf.Close()
	preader, err := gzip.NewReader(pcapf)
	if err != nil {
		log.Fatal(err)
	}
	defer preader.Close()
	pcapreader, err := pcapgo.NewReader(preader)
	if err != nil {
		log.Fatal(err)
	}

	//	var wg sync.WaitGroup
	for {
		data, ci, err := pcapreader.ZeroCopyReadPacketData()
		if err == nil {

			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			srcip := pkt.NetworkLayer().NetworkFlow().Src().String()
			dstip := pkt.NetworkLayer().NetworkFlow().Dst().String()
			probetime := ci.Timestamp
			ttl := pkt.NetworkLayer().(*layers.IPv4).TTL
			//pkt.Metadata().Timestamp
			timetrunc := 5 * time.Minute
			timeform := "2006-01-02 03:04"
			onlinemap.Lock.Lock()
			if _, srcexist := onlinemap.Hostmap[srcip]; !srcexist {

				onlinemap.Hostmap[srcip] = make(map[string][]*ProbeDetails)
				//	onlinemap[srcip][probetime.Truncate(24*time.Hour).Format("2006-01-02")] = append(onlinemap[srcip][probetime.Truncate(24*time.Hour).Format("2006-01-02")], &ProbeDetails{ProbeIP: dstip, ProbeTime: probetime})
			}
			onlinemap.Hostmap[srcip][probetime.Truncate(timetrunc).Format(timeform)] = append(onlinemap.Hostmap[srcip][probetime.Truncate(timetrunc).Format(timeform)], &ProbeDetails{ProbeIP: dstip, ProbeTime: probetime, Ttl: ttl})
			onlinemap.Lock.Unlock()
		} else {
			break
		}
	}

	//	wg.Wait()

}
