package greynetanalysis

import (
	"github.com/CAIDA/goiputils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func IsZmap(p gopacket.Packet) bool {
	if ipl4 := p.Layer(layers.LayerTypeIPv4); ipl4 != nil {
		ipl, _ := ipl4.(*layers.IPv4)
		return ipl.Id == 54321
	} else {
		return false
	}
}

func IsMasscan(p gopacket.Packet) bool {
	//ipid = dstip XOR dstport XOR tcpseq
	ipl4 := p.Layer(layers.LayerTypeIPv4)
	tcpl := p.Layer(layers.LayerTypeTCP)

	if ipl4 != nil && tcpl != nil {
		ipl, _ := ipl4.(*layers.IPv4)
		tcph, _ := tcpl.(*layers.TCP)
		dst32, _ := goiputils.IPv4ToInt(ipl.DstIP)
		dstipu16 := uint16(dst32)
		tcpseq16 := uint16(tcph.Seq)
		dport := (uint16)(tcph.DstPort)
		eipid := dstipu16 ^ tcpseq16 ^ dport
		return ipl.Id == eipid
	} else {
		return false
	}
}

func IsMirai(p gopacket.Packet) bool {
	//tcp seq == dstip
	ipl4 := p.Layer(layers.LayerTypeIPv4)
	tcpl := p.Layer(layers.LayerTypeTCP)
	if ipl4 != nil && tcpl != nil {
		ipl, _ := ipl4.(*layers.IPv4)
		tcph, _ := tcpl.(*layers.TCP)
		dst32, _ := goiputils.IPv4ToInt(ipl.DstIP)
		return dst32 == tcph.Seq
	} else {
		return false
	}
}

func IsBogon(p gopacket.Packet) bool {
	ipl4 := p.Layer(layers.LayerTypeIPv4)
	if ipl4 != nil {
		iph := ipl4.(*layers.IPv4)
		return iph.SrcIP.IsUnspecified() || iph.SrcIP.IsPrivate() || iph.SrcIP.IsMulticast() || iph.SrcIP.IsLoopback()
	}
	return false
}
