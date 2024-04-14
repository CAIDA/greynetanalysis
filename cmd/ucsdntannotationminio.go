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
	"sync/atomic"
)

type TrafficStat struct {
	KnownTraffic map[string]uint64
	KTMutex *sync.RWMutex
	Mirai uint64
	Zmap uint64
	Masscan uint64
	Bogon uint64
	Asn map[string]uint64
	ASMutex *sync.RWMutex
	Country map[string]uint64
	CCMutex *sync.RWMutex
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
	tstat.KnownTraffic = make(map[string]uint64)
	tstat.KTMutex = &sync.RWMutex{}
	tstat.Asn = make(map[string]uint64)
	tstat.ASMutex = &sync.RWMutex{}
	tstat.CCMutex = &sync.RWMutex{}

	tstat.Country = make(map[string]uint64)
	var wg sync.WaitGroup
	jwchan :=make(chan int, 100000)
	for scanner.Scan(){
		obj := scanner.Text()
		jwchan<-1
		wg.Add(1)
		go func(b string){
			var pktan *greynetanalysis.PacketAnnotation
			json.Unmarshal([]byte(b), &pktan)
			if pktan.IsZmap {
				atomic.AddUint64(&tstat.Zmap,1)
			}
			if pktan.IsMasscan {
				atomic.AddUint64(&tstat.Masscan ,1)
			}
			if pktan.IsMirai {
				atomic.AddUint64(&tstat.Mirai, 1)
			}
			if pktan.IsBogon {
				atomic.AddUint64(&tstat.Bogon, 1)
			}
			tstat.ASMutex.Lock()
			tstat.Asn[pktan.SrcASN] += 1
			tstat.ASMutex.Unlock()
			tstat.CCMutex.Lock()
			tstat.Country[pktan.MaxmindCountry] += 1
			tstat.CCMutex.Unlock()
			ksarr := strings.Split(pktan.KnownScanner, "|")
			for _, ks := range ksarr{
				if len(ks)>0{
					tstat.KTMutex.Lock()
					tstat.KnownTraffic[ks]+=1
					//log.Println(tstat.KnownTraffic)
					tstat.KTMutex.Unlock()
				}
			}
			wg.Done()
			<-jwchan
		}(obj)

	}
	wg.Wait()
	f.WriteString(fmt.Sprintf("zmap,%d\n",tstat.Mirai))
	f.WriteString(fmt.Sprintf("masscan,%d\n",tstat.Masscan))
	f.WriteString(fmt.Sprintf("bogon,%d\n",tstat.Bogon))
	for asn, asnt := range tstat.Asn {
		f.WriteString(fmt.Sprintf("asn,%s,%d\n",asn, asnt))
	}

	for known, knownt := range tstat.KnownTraffic{
		f.WriteString(fmt.Sprintf("known,%s,%d\n",known, knownt))
	}
	for cc, cct := range tstat.Country {
		f.WriteString(fmt.Sprintf("cc,%s,%d\n",cc, cct))
	}
	f.Sync()
	log.Println("writing final bits")
}
