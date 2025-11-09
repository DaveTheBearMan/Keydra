package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// Log commands
var logRoot = &cobra.Command{
	Use:   "log",
	Short: "Operations for Keydra logs",
}

var readRoot = &cobra.Command{
	Use:   "read",
	Short: "Read from database",
	Long:  "Read operations for the keydra cli for logs",
}

var readChannel = &cobra.Command{
	Use:   "channel [channel] [n]",
	Short: "Read a log channel",
	Long:  "Reads the last N messages from a given Redis log channel (stream).",
	Args:  cobra.ExactArgs(2),
	Run:   readLogChannelFunc,
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

func AttachLogCommands(rootCmd *cobra.Command) {
	// Build log cli object
	readRoot.AddCommand(readChannel)
	logRoot.AddCommand(readRoot)

	// Attach to main
	rootCmd.AddCommand(logRoot)
}
