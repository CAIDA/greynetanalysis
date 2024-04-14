package main

import (
	"flag"
	"fmt"
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
	rwm := sync.RWMutex{}
	onlinemap := greynetanalysis.OnlineMap{Lock: &rwm}

	onlinemap.Hostmap = make(map[string]map[string][]*greynetanalysis.ProbeDetails)
	for _, file := range files {
		if re.MatchString(file.Name()) {
			log.Println("found pcap file", file)
			workchan <- 1
			wg.Add(1)
			go func(pfile string) {
				greynetanalysis.Processpcap_onlinemap(pfile, onlinemap)
				wg.Done()
				<-workchan
			}(filepath.Join(pcapfolder, file.Name()))

		}
	}
	wg.Wait()
	Printonlinemap(onlinemap)
}

func Printonlinemap(onlinemap greynetanalysis.OnlineMap) {
	for srcip, datemap := range onlinemap.Hostmap {
		for date, probelist := range datemap {
			fmt.Println(srcip, ",", date, ",", len(probelist))
			/*for _, probe := range probelist {
				fmt.Println("-", probe.ProbeTime, probe.ProbeIP)
			}*/
		}
	}
}
