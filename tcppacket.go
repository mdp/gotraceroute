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

func startPCAP(status chan int) {
	if handle, err := pcap.OpenLive("en0", 65536, false, 1); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("icmp and icmp[0] == 11"); err != nil { // Type 11 is TTLExceeded
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		status <- 0
		for packet := range packetSource.Packets() {
			fmt.Printf("%s", packet)
			close(status)
		}
	}
}

func firePacket() {
	var dst string
	ttl := flag.Int("ttl", 64, "the TTL on the packet")
	flag.Parse()
	dst = flag.Args()[0]
	dstaddrs, err := net.LookupIP(dst)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TTL: %s", *ttl)
	// parse the destination host and port from the command line os.Args
	dstip := dstaddrs[0].To4()
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
		log.Fatalf("Dialing didn't dial: %s\n", err)
	}
	if err = ipv4.NewPacketConn(conn).SetTTL(*ttl); err != nil {
		log.Fatalf("I had a difficult experience setting the TTL: %s\n", err)
	}
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Sent")
}

func main() {
	status := make(chan int)
	go startPCAP(status)
	go (func() {
		time.Sleep(10 * time.Second)
		fmt.Println("Timeout")
		os.Exit(1)
	})()
	for _ = range status {
		fmt.Println("FirePacket")
		firePacket()
	}
}
