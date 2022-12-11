# greynetanalysis
Annotate and analysis pcaps collected from UCSD telescope.

## Dependencies
Require access to two private CAIDA's git repos and access to CAIDA's swift storage.
```
github.com/CAIDA/goiputils
github.com/CAIDA/gostardust/gostardustswift
```

## Modules
### tagpackets.go
contains the logic for fields `IsZamp`, `IsMassscan`, `IsMirai`, and `IsBogon`

### cmd/knowscanner.yaml
This YAML file contains the list of IPs/IP prefix/hostnames of known scanners.
