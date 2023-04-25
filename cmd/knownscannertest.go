package main

import (
	"fmt"
	"greynetanalysis"
	"log"
	"net"
	"time"
)

func main() {

	//	known := greynetanalysis.LoadKnownScanners("knownscanner.yaml")
	log.Println("start")
	known := greynetanalysis.NewKnownScanners()
	known.AddSource("knownscanner.yaml", "other")
	known.AddSource("mcscanner.yaml", "other")
	known.AddSource("data/gn.yaml", "timed")
	known.AddSource("data/alienvault.csv", "csv")
	log.Println("lib completed")
	fmt.Println(known.Check(net.IP{162, 142, 125, 3}, "", time.Date(2023, 3, 31, 0, 0, 0, 0, time.UTC)))
	fmt.Println(known.Check(net.IP{71, 6, 167, 142}, "", time.Date(2023, 3, 31, 0, 0, 0, 0, time.UTC)))
	fmt.Println(known.Check(net.IP{198, 143, 133, 154}, "server1.phx.internet-census.org.", time.Date(2023, 3, 31, 0, 0, 0, 0, time.UTC)))
	fmt.Println(known.Check(net.IP{151, 247, 53, 163}, "", time.Date(2023, 4, 2, 0, 0, 0, 0, time.UTC)))
	fmt.Println(known.Check(net.IP{71, 6, 233, 1}, "", time.Date(2023, 4, 2, 0, 0, 0, 0, time.UTC)))
	fmt.Println(known.Check(net.IP{190, 199, 111, 8}, "", time.Date(2023, 4, 2, 0, 0, 0, 0, time.UTC)))
	log.Println("end")
}
