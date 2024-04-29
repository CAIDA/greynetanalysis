package main

import (
	"flag"
	"fmt"
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
			fmt.Println(k, v.PckCount, len(v.Dest), len(v.Port))
		}
	}
}
