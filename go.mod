module greynetanalysis

go 1.19

require (
	github.com/CAIDA/goiputils v0.0.0
	github.com/CAIDA/gostardust/gostardustswift v0.0.0-00010101000000-000000000000
	github.com/CAIDA/greynoiseapi v0.0.0
	github.com/google/gopacket v1.1.19
	github.com/zmap/go-iptree v0.0.0-20210731043055-d4e632617837
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/asergeyev/nradix v0.0.0-20170505151046-3872ab85bb56 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/ncw/swift/v2 v2.0.1 // indirect
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859 // indirect
	golang.org/x/sys v0.0.0-20190412213103-97732733099d // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/CAIDA/goiputils => ../goiputils

replace github.com/CAIDA/greynoiseapi => ../greynoiseapi

replace github.com/CAIDA/gostardust/gostardustswift => ../gostardust/gostardustswift
