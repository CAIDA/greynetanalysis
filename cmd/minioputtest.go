package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"greynetanalysis"
	"io"
	"log"
	"sync"
)

type TestStruct struct {
	Seq int
}

func main() {

	ctx := context.Background()
	gmio := greynetanalysis.NewGreynetMinioiwthContext(ctx)
	r, w := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		up := gmio.PutMetaData("test.txt.gz", r)
		log.Println(up)
		wg.Done()
	}()
	gzwrite := gzip.NewWriter(w)
	for i := 0; i < 3000; i++ {
		t := TestStruct{Seq: i}
		b, _ := json.Marshal(t)
		b = append(b, '\n')
		//		b := []byte(str)
		gzwrite.Write(b)
		//		fmt.Fprintf(w, "some io.Reader stream to be read line %d\n", i)
	}
	gzwrite.Flush()
	gzwrite.Close()
	w.Close()
	wg.Wait()
}
