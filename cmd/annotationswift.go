package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"greynetanalysis"
	"log"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/CAIDA/goiputils"
	"github.com/CAIDA/gostardust/gostardustswift"
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
	var start, end time.Time
	ctx := context.Background()
	flag.Func("start", "start date", func(s string) error {
		if len(s) == 0 {
			start = time.Time{}
			return nil
		}
		ts, err := time.Parse("2006-01-02", s)
		if err != nil {
			return err
		}
		start = ts
		return nil
	})
	flag.Func("end", "end date", func(s string) error {
		if len(s) == 0 {
			end = time.Now()
			return nil
		}
		ts, err := time.Parse("2006-01-02", s)
		if err != nil {
			return err
		}
		end = ts.AddDate(0, 0, 1).Add(-1 * time.Nanosecond)
		return nil
	})

	flag.Parse()
	renames := regexp.MustCompile(gostardustswift.NameRegex)
	sdswift := gostardustswift.NewStarDustSwiftConnectionWithContext(ctx)
	allnames := make([]string, 0)
	filterednames := make([]string, 0)
	greynames, err := sdswift.GetGreynetGreyPcapNamesAll()
	if err != nil {
		log.Fatal("get greynetpcapnames failed", err)
	}

	allnames = append(allnames, greynames...)
	darknames, err := sdswift.GetGreynetDarkPcapNamesAll()
	if err != nil {
		log.Fatal("get darknetpcapnames failed", err)
	}

	allnames = append(allnames, darknames...)
	histnames, err := sdswift.GetGreynetHistoryPcapNamesAll()
	if err != nil {
		log.Fatal("get historic pcapnames failed", err)
	}
	allnames = append(allnames, histnames...)

	//filter files within time range
	for _, f := range allnames {
		fts, err := extractfiledate(renames, f, 2)
		if err == nil {
			if !(fts.Before(start) || fts.After(end)) {
				filterednames = append(filterednames, f)
			}
		}
	}
	sort.Slice(filterednames, func(i, j int) bool {
		its, _ := extractfiledate(renames, filterednames[i], 2)
		jts, _ := extractfiledate(renames, filterednames[j], 2)
		/*		itsstr := renames.FindStringSubmatch(allnames[i])
				jtsstr := renames.FindStringSubmatch(allnames[j])
				itsint, _ := strconv.ParseInt(itsstr[2], 10, 64)
				jtsint, _ := strconv.ParseInt(jtsstr[2], 10, 64)*/
		return its.Before(jts)
	})
	curipinfo := &IPInfo{}
	//fixed knownscanner file
	curipinfo.KnownScanner = greynetanalysis.LoadKnownScanners("knownscanner.yaml")
	var wgdate sync.WaitGroup
	/*	for i, f := range filterednames {
			fmt.Println(i, f)
		}
		return*/
	for _, f := range filterednames {
		tmpdate, err := extractfiledate(renames, f, 2)
		tmpdate = time.Date(tmpdate.Year(), tmpdate.Month(), tmpdate.Day(), 0, 0, 0, 0, time.UTC)
		if err == nil {
			//load pfx2as maxmind and netacq tree of this day
			if !curipinfo.CurDate.Equal(tmpdate) {
				//finish the processing of the previous date first
				wgdate.Wait()
				curipinfo.CurDate = tmpdate
				log.Println("loading data structure for day", curipinfo.CurDate)
				curipinfo.Pfx2asn = goiputils.NewIPHandlerbyDate(curipinfo.CurDate)
				curipinfo.Mmgeo = goiputils.NewMaxmindCAIDA(ctx, curipinfo.CurDate, "en")
				curipinfo.Naqgeo = goiputils.NewNetacqCAIDA(ctx, curipinfo.CurDate)
				log.Println("completed loading data structure")
				//reload the auth info
				sdswift = gostardustswift.NewStarDustSwiftConnectionWithContext(ctx)
			}
			wgdate.Add(1)
			go processfile(&wgdate, sdswift, curipinfo, f)
		} else {
			log.Println("extract file ts error", f, err)
		}
	}
	log.Println("processing last batch")
	wgdate.Wait()
	/*
		pcapf, err := os.Open("test.pcap")
		if err != nil {
			log.Fatal(err)
		}
		defer pcapf.Close()
		pcapreader, err := pcapgo.NewReader(pcapf)
		if err != nil {
			log.Fatal(err)
		}
		var knownscan *greynetanalysis.KnownScanners
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
	*/
}

func extractfiledate(re *regexp.Regexp, f string, tsidx int) (time.Time, error) {
	tsstr := re.FindStringSubmatch(f)
	if len(tsstr) > tsidx {
		thists, err := strconv.ParseInt(tsstr[tsidx], 10, 64)
		if err != nil {
			return time.Time{}, errors.New("failed to parse timestamp")
		}
		return time.Unix(thists, 0), nil
	} else {
		return time.Time{}, errors.New("ts index exceed length")
	}

}

func processfile(wgdate *sync.WaitGroup, sdswift *gostardustswift.StarDustSwift, ipinfo *IPInfo, filepath string) {
	var wg, wgchan sync.WaitGroup
	defer wgdate.Done()
	log.Println("processing file:", filepath)
	pcapgz := sdswift.GetGreyPcapByPath(filepath)
	pbuf := bytes.NewBuffer(pcapgz)
	preader, err := gzip.NewReader(pbuf)
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
	allinfo := make([]*greynetanalysis.PacketAnnotation, 0)
	infochan := make(chan *greynetanalysis.PacketAnnotation, 1000)
	wgchan.Add(1)
	go func() {
		for a := range infochan {
			allinfo = append(allinfo, a)
		}
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
			//			fmt.Println("zmap:", greynetanalysis.IsZmap(pkt), "masscan:", greynetanalysis.IsMasscan(pkt), "mirai:", greynetanalysis.IsMirai(pkt))
		} else {
			break
		}
	}
	wg.Wait()
	close(infochan)
	wgchan.Wait()
	//finished processing
	//sort the slice by packet number
	sort.Slice(allinfo, func(i, j int) bool {
		return allinfo[i].PacketCnt < allinfo[j].PacketCnt
	})

	renames := regexp.MustCompile(gostardustswift.NameRegex)
	jts, _ := extractfiledate(renames, filepath, 2)
	fstr := renames.FindStringSubmatch(filepath)
	jname := fstr[1]

	jinfo, err := json.Marshal(allinfo)
	if err != nil {
		log.Println("json marshal error", filepath, err)
	}
	var bjson bytes.Buffer
	//	bjson := bytes.NewBuffer(jinfo)
	gzwrite := gzip.NewWriter(&bjson)
	_, _ = gzwrite.Write(jinfo)
	gzwrite.Flush()
	gzwrite.Close()
	_, err = sdswift.PutGreynetAnnotation(jts, jname, &bjson)
	if err != nil {
		log.Println("greynetannotation error", err)
	}
}
