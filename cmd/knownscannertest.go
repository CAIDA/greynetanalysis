package main

import (
	"fmt"
	"greynetanalysis"
	"net"
)

func main() {

	known := greynetanalysis.LoadKnownScanners("knownscanner.yaml")
	fmt.Println(known.Check(net.IP{162, 142, 125, 3}, ""))
	fmt.Println(known.Check(net.IP{71, 6, 167, 142}, ""))
	fmt.Println(known.Check(net.IP{198, 143, 133, 154}, "server1.phx.internet-census.org."))
}
