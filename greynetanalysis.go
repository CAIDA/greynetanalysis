package greynetanalysis

import (
	"net"
	"strings"
	"time"

	"github.com/CAIDA/goiputils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const GREYNETCONTAINER = "telescope-ucsdnt-pcap-greynet"

type PacketSummary struct {
	PacketAnnotation
	Timestamp time.Time
	Proto     uint16
	Port      uint16
	Size      uint16
}

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

func AnnotatePacketwithSummary(p gopacket.Packet, cnt int, pfx2asn goiputils.IPHandler, mmgeo, naqgeo goiputils.IPMetaProvider, ks *KnownScanners) *PacketSummary {
	if p != nil {
		ipl4 := p.Layer(layers.LayerTypeIPv4)
		if ipl4 != nil {
			pckan := AnnotatePacket(p, cnt, pfx2asn, mmgeo, naqgeo, ks)
			pcksum := &PacketSummary{PacketAnnotation: *pckan}
			iph, _ := ipl4.(*layers.IPv4)
			pcksum.Proto = uint16(iph.Protocol)
			pcksum.Size = uint16(iph.Length)
			switch iph.Protocol {
			case layers.IPProtocolTCP:
				tcpl := p.Layer(layers.LayerTypeTCP)
				if tcpl != nil {
					tcph, _ := tcpl.(*layers.TCP)
					pcksum.Port = uint16(tcph.DstPort)
				}
			case layers.IPProtocolUDP:
				udpl := p.Layer(layers.LayerTypeUDP)
				if udpl != nil {
					udph, _ := udpl.(*layers.UDP)
					pcksum.Port = uint16(udph.DstPort)
				}
			case layers.IPProtocolICMPv4:
				icmpl := p.Layer(layers.LayerTypeICMPv4)
				if icmpl != nil {
					icmph, _ := icmpl.(*layers.ICMPv4)
					pcksum.Port = uint16(icmph.TypeCode)
				}
			default:
				pcksum.Port = 0
			}
			return pcksum
		}
	}
	return nil
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
				AnnotateSrcIP(iph.SrcIP, p.Metadata().Timestamp, pckan, pfx2asn, mmgeo, naqgeo, ks)
			}
		}
		return pckan
	}
	return nil
}

func AnnotateSrcIP(srcip net.IP, ts time.Time, pckan *PacketAnnotation, pfx2asn goiputils.IPHandler, mmgeo, naqgeo goiputils.IPMetaProvider, ks *KnownScanners) {
	if pckan != nil && pfx2asn != nil && mmgeo != nil && naqgeo != nil {
		pckan.SrcASN = pfx2asn.IPtoASNLocal(srcip)
		pckan.HostName = pfx2asn.ResolveName(srcip)
		if naqr := naqgeo.LookupIP(srcip); naqr != nil {
			naqresult := naqr.(*goiputils.NetacqLocation)
			pckan.NetacqCountry = naqresult.CountryISO
		} else {
			pckan.NetacqCountry = "??"
		}
		if mmr := mmgeo.LookupIP(srcip); mmr != nil {
			mmresult := mmr.(*goiputils.MaxmindOutput)
			pckan.MaxmindCountry = mmresult.CountryISO
		} else {
			pckan.MaxmindCountry = "??"
		}
		pckan.KnownScanner = strings.Join(ks.Check(srcip, pckan.HostName, ts), "|")
	}
}
