package greynetanalysis

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

//GreynetMinio defines minio object
type GreynetMinio struct {
	client                                *minio.Client
	endpoint, bucket, accessid, accesskey string
	Ctx                                   context.Context
}

const STARDUSTBUCKETNAME = "imc-paper-stardust"
const ENDPOINTVAR = "MIO_ENDPOINT"
const ACCESSKEYVAR = "MIO_ACCESS_KEY_ID"
const SECRETKEYVAR = "MIO_SECRET_KEY"

//NewGreynetMinioiwthContext initials minio object
func NewGreynetMinioiwthContext(ctx context.Context) GreynetMinio {
	var err error
	g := GreynetMinio{Ctx: ctx}
	//read from environment variables
	g.endpoint = os.Getenv(ENDPOINTVAR)
	g.accessid = os.Getenv(ACCESSKEYVAR)
	g.accesskey = os.Getenv(SECRETKEYVAR)
	g.bucket = STARDUSTBUCKETNAME
	log.Println(g)
	g.client, err = minio.New(g.endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(g.accessid, g.accesskey, ""),
		Secure: true,
	})
	if err != nil {
		log.Fatal("failed to init minio", err)
	}
	return g
}

func (gmio GreynetMinio) ListNTpcapsbyDate(d time.Time) []string {
	ctx, cancel := context.WithCancel(gmio.Ctx)
	defer cancel()
	objprefix := fmt.Sprintf("datasource=ucsd-nt/year=%d/month=%02d/day=%02d", d.Year(), d.Month(), d.Day())
	objchan := gmio.client.ListObjects(ctx, gmio.bucket, minio.ListObjectsOptions{
		Prefix:    objprefix,
		Recursive: true,
	})
	objs := make([]string, 0)
	for object := range objchan {
		if object.Err != nil {
			log.Println("list object error", object.Err)
		} else {
			//only list pcap files
			if strings.Contains(object.Key, ".pcap") {
				objs = append(objs, object.Key)
			}
		}
	}
	return objs
}

func (gmio GreynetMinio) GetObject(objpath string) *minio.Object {
	object, err := gmio.client.GetObject(gmio.Ctx, gmio.bucket, objpath, minio.GetObjectOptions{})
	if err != nil {
		log.Println(err)
		return nil
	}
	return object
}

func (gmio GreynetMinio) PutMetaData(objpath string, reader io.Reader) minio.UploadInfo {
	log.Println("putmetadata starts", objpath)
	uploadinfo, err := gmio.client.PutObject(gmio.Ctx, gmio.bucket, objpath, reader, -1, minio.PutObjectOptions{ContentType: "application/json", ContentEncoding: "gzip"})
	//uploadinfo, err := gmio.client.PutObject(gmio.Ctx, gmio.bucket, objpath, reader, -1, minio.PutObjectOptions{})
	if err != nil {
		log.Println("upload", objpath, "error", err)
	}
	//log.Println("uploaded", uploadinfo)
	return uploadinfo
}
