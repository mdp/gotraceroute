package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"golang.org/x/net/ipv4"

	"code.google.com/p/gopacket/layers"
)

func lookupIPv4(host string) net.IP {
	dstaddrs, err := net.LookupIP(host)
	if err != nil {
		log.Fatal(err)
	}
	for _, addr := range dstaddrs {
		ipv4 := addr.To4()
		if ipv4 != nil {
			return ipv4
		}
	}
	return nil
}

func localIPPort(dstip net.IP) (net.IP, int) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}
	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port
		}
	}
	log.Fatal("could not get local ip: " + err.Error())
	return nil, -1
}

func TCPPacket(dstip net.IP, port int16) *layers.TCP {
	dstport := layers.TCPPort(port)
	srcip, sport := localIPPort(dstip)
	srcport := layers.TCPPort(sport)

	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     rand.Uint32(),
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	return tcp
}

func listenICMP(status chan int) {
	var handle *pcap.Handle
	interfaces := []string{"en0", "eth0"}
	for _, i := range interfaces {
		if h, err := pcap.OpenLive(i, 65536, false, 1); err == nil {
			handle = h
			break
		}
		panic("No valid interface found")
	}
	if err := handle.SetBPFFilter("icmp and icmp[0] == 11"); err != nil { // Type 11 is TTLExceeded
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		status <- 0
		for packet := range packetSource.Packets() {
			src := packet.NetworkLayer().NetworkFlow().Src()
			fmt.Printf("ICMP TTL Exceeded from IP: %s ", src)
			if host, err := net.LookupAddr(src.String()); err == nil {
				fmt.Printf("Host: %s\n", host[0])
			}
			close(status)
		}
	}
}

func firePacket(dst string, ttl *int) {
	dstip := lookupIPv4(dst)
	packet := TCPPacket(dstip, 80)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, packet); err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		log.Fatalf("ListenPacket failed to listen: %s\n", err)
	}
	if err = ipv4.NewPacketConn(conn).SetTTL(*ttl); err != nil {
		log.Fatalf("I had a difficult experience setting the TTL: %s\n", err)
	}
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Fired Packet at %s with a ttl of %d\n", dstip, *ttl)
}

func main() {
	ttl := flag.Int("ttl", 64, "the TTL on the packet")
	flag.Parse()
	dst := flag.Args()[0]
	status := make(chan int)
	go listenICMP(status)
	go (func() {
		time.Sleep(10 * time.Second)
		fmt.Println("Timeout")
		os.Exit(1)
	})()
	for _ = range status {
		firePacket(dst, ttl)
	}
}
