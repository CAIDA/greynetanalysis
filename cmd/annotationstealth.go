package main

import (
	"flag"
	"greynetanalysis"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

func main() {
	var pcapfolder string
	flag.StringVar(&pcapfolder, "d", "/scratch/passive_trace/stealthscan/", "dir to pcaps")
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
			log.Println("found pcap file", file)
			workchan <- 1
			wg.Add(1)
			go func(pfile string) {
				greynetanalysis.Processpcap_annotation(pfile)
				wg.Done()
				<-workchan
			}(filepath.Join(pcapfolder, file.Name()))

		}
	}
	wg.Wait()
}
