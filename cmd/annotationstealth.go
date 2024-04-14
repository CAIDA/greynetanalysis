package main

import (
	"context"
	"greynetanalysis"
	"log"
	"os"
	"sync"
	"regexp"
	"flag"
	"encoding/json"
	"compress/gzip"
	"path/filepath"

	"github.com/CAIDA/goiputils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	var pcapfolder string
	flag.StringVar(&pcapfolder, "d", "/scratch/passive_trace/stealthscan/","dir to pcaps")
	flag.Parse()
	files, err := os.ReadDir(pcapfolder)
	if err != nil {
		log.Fatal(err)
	}
	worker := 10
	workchan := make(chan int, worker)
	var wg sync.WaitGroup
	re := regexp.MustCompile(`ucsd-nt\.\d+\.pcap\.gz`)
	for _, file := range files {
		if re.MatchString(file.Name()) {
			log.Println("found pcap file",file)
			workchan <- 1
			wg.Add(1)
			go func(pfile string){
				processpcap(pfile)
				wg.Done()
				<-workchan
			}(filepath.Join(pcapfolder,file.Name()))

		}
	}
	wg.Wait()
}


func processpcap(pcapgzfile string) {

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
	var known *greynetanalysis.KnownScanners
	annotations := make([]*greynetanalysis.PacketAnnotation, 0, 0)
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
				known = greynetanalysis.NewKnownScanners()
				//known.AddSource("knownscanner.yaml", "other")
				//known.AddSource("mcscanner.yaml", "other")
				//known.AddSource("data/gn.yaml", "timed")
				//known.AddSource("data/alienvault.csv", "csv")

			}
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			//			wg.Add(1)
			//			go func(pkt gopacket.Packet, cnt int) {
			annotations = append(annotations, greynetanalysis.AnnotatePacket(pkt, cnt, pfx2asn, mmgeo, naqgeo, known))
			//				fmt.Println(annotation)
			//				wg.Done()
			//			}(pkt, cnt)
			cnt += 1
			//			fmt.Println("zmap:", greynetanalysis.IsZmap(pkt), "masscan:", greynetanalysis.IsMasscan(pkt), "mirai:", greynetanalysis.IsMirai(pkt))
		} else {
			break
		}
	}
	annotationfilename := pcapgzfile[:len(pcapgzfile)-8]+".json.gz"
	//	wg.Wait()
	afile, err := os.Create(annotationfilename)
	if err != nil {
		log.Fatal(err)
	}
	defer afile.Close()
	jinfo, err := json.Marshal(annotations)
	if err !=nil  {
		log.Println("json marshal error", pcapgzfile, err)
	}
	gzwrite := gzip.NewWriter(afile)
	_, _ = gzwrite.Write(jinfo)
	gzwrite.Flush()
	gzwrite.Close()
}


