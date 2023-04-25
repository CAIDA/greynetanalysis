package greynetanalysis

import (
	"strings"

	"github.com/CAIDA/goiputils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const GREYNETCONTAINER = "telescope-ucsdnt-pcap-greynet"

type PacketAnnotation struct {
	PacketCnt      int
	IsZmap         bool
	IsMasscan      bool
	IsMirai        bool
	IsBogon        bool
	SrcASN         string
	HostName       string
	NetacqCountry  string
	MaxmindCountry string
	KnownScanner   string
}

func AnnotatePacket(p gopacket.Packet, cnt int, pfx2asn goiputils.IPHandler, mmgeo, naqgeo goiputils.IPMetaProvider, ks *KnownScanners) *PacketAnnotation {
	if p != nil {
		pckan := &PacketAnnotation{PacketCnt: cnt}
		pckan.IsZmap = IsZmap(p)
		pckan.IsMasscan = IsMasscan(p)
		pckan.IsMirai = IsMirai(p)
		pckan.IsBogon = IsBogon(p)
		if pfx2asn != nil && mmgeo != nil && naqgeo != nil {
			ipl4 := p.Layer(layers.LayerTypeIPv4)
			if ipl4 != nil {
				iph, _ := ipl4.(*layers.IPv4)
				pckan.SrcASN = pfx2asn.IPtoASNLocal(iph.SrcIP)
				pckan.HostName = pfx2asn.ResolveName(iph.SrcIP)
				if naqr := naqgeo.LookupIP(iph.SrcIP); naqr != nil {
					naqresult := naqr.(*goiputils.NetacqLocation)
					pckan.NetacqCountry = naqresult.CountryISO
				} else {
					pckan.NetacqCountry = "??"
				}
				if mmr := mmgeo.LookupIP(iph.SrcIP); mmr != nil {
					mmresult := mmr.(*goiputils.MaxmindOutput)
					pckan.MaxmindCountry = mmresult.CountryISO
				} else {
					pckan.MaxmindCountry = "??"
				}

				pckan.KnownScanner = strings.Join(ks.Check(iph.SrcIP, pckan.HostName, p.Metadata().Timestamp), "|")
				return pckan
			}
		}
		return pckan
	}
	return nil
}
