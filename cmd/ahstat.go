package main

import (
	"flag"
	"greynetanalysis"
)

func main() {
	var filestr string
	flag.StringVar(&filestr, "o", "", "file")
	flag.Parse()
	if filestr == "" {
		flag.PrintDefaults()
		return
	}
	scprofile := greynetanalysis.ReadScannerProfile(filestr)
	for k, v := range scprofile {
		if v.PckCount > 0 {
			println(k, v.PckCount)
		}
	}
}
