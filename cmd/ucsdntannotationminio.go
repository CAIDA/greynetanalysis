package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"greynetanalysis"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"bufio"
	"os"
)

type TrafficStat struct {
	KnownTraffic map[string]int
	Mirai int
	Zmap int
	Masscan int
	Bogon int
	Asn map[string]int
	Country map[string]int
} 


var nworkers int

func main() {
	ctx := context.Background()
	gmio := greynetanalysis.NewGreynetMinioiwthContext(ctx)
	var startstr, endstr string
	flag.StringVar(&startstr, "start", "2023-03-27 00:00", "start date")
	flag.StringVar(&endstr, "end", "2023-04-03 00:00", "end date")
	flag.IntVar(&nworkers, "w", 10, "number of workers")
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
	wchan := make(chan int, nworkers)
	for cdate := startts; cdate.Before(endts); cdate = cdate.AddDate(0, 0, 1) {

		for _, f := range gmio.ListNTannotationbyDate(cdate) {

			name := filepath.Base(f)
			nameparts := strings.Split(name, `.`)
			ts, _ := strconv.ParseInt(nameparts[1], 10, 64)
			fts := time.Unix(ts, 0)
			if (fts.After(cdate) || fts.Equal(cdate)) && fts.Before(endts) {
				fmt.Println(f)
				wchan <- 1
				wg.Add(1)
				go func (f string){
					processmioannotationfile(gmio, f)
					wg.Done()
					<-wchan
				}(f)
			}
		}
	}
	log.Println("finished all")
	wg.Wait()
}

func processmioannotationfile(gmio greynetanalysis.GreynetMinio, filep string) {
	log.Println("processing file:", filep)
	pcapgz := gmio.GetObject(filep)
	//	pbuf := bytes.NewBuffer(pcapgz)
	preader, err := gzip.NewReader(pcapgz)
	if err != nil {
		log.Println(err)
		return
	}
	defer preader.Close()
	statfilename := filepath.Base(filep)
	statfilename = "/scratch/passive_trace/stat/"+statfilename[:len(statfilename)-9]+".stat.csv"
	log.Println("output:",statfilename)
	f, err := os.Create(statfilename)
	if err != nil {
		log.Fatal("cannot write file", statfilename)
	}
	defer f.Close()

	scanner := bufio.NewScanner(preader)
	tstat := &TrafficStat{Mirai:0 ,Zmap:0, Masscan:0 , Bogon:0}
	tstat.KnownTraffic = make(map[string]int)
	tstat.Asn = make(map[string]int)
	tstat.Country = make(map[string]int)
	for scanner.Scan(){
		var pktan *greynetanalysis.PacketAnnotation
		json.Unmarshal(scanner.Bytes(), &pktan)
		if pktan.IsZmap {
			tstat.Zmap +=1
		}
		if pktan.IsMasscan {
			tstat.Masscan += 1
		}
		if pktan.IsMirai {
			tstat.Mirai += 1
		}
		if pktan.IsBogon {
			tstat.Bogon += 1
		}
		tstat.Asn[pktan.SrcASN] += 1
		tstat.Country[pktan.MaxmindCountry] += 1
		ksarr := strings.Split(pktan.KnownScanner, "|")
		for _, ks := range ksarr{
			if len(ks)>0{
				tstat.KnownTraffic[ks]+=1
			}
		}

	}
		f.WriteString(fmt.Sprintf("zmap,%d",tstat.Mirai))
	f.WriteString(fmt.Sprintf("masscan,%d",tstat.Masscan))
	f.WriteString(fmt.Sprintf("bogon,%d",tstat.Bogon))
	for asn, asnt := range tstat.Asn {
		f.WriteString(fmt.Sprintf("asn,%s,%d",asn, asnt))
	}

	for known, knownt := range tstat.KnownTraffic{
		f.WriteString(fmt.Sprintf("known,%s,%d",known, knownt))
	}
	for cc, cct := range tstat.Country {
		f.WriteString(fmt.Sprintf("cc,%s,%d",cc, cct))
	}
	f.Sync()
	log.Println("writing final bits")
}
