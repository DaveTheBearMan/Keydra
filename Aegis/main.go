package main

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
)

// Types
type PayloadScript struct {
	FilePath    string `json:"file_path"`
	EncodedData string `json:"encoded_data"`
}

var (
	rdb    *redis.Client
	ctx    = context.Background()
	UserId = 1
)

// Connect to Redis before running commands
func connectToServerRDB(cmd *cobra.Command, args []string) {
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // adjust if Redis is remote
	})
}

// Root command
var rootCmd = &cobra.Command{
	Use:   "aegis",
	Short: "Handles the Keydra server",
	Long: `Aegis is a cli for controlling Keydra servers for clients communicated with over raw socket UDP.

The goal is to bypass host level firewall rules through the use of eBPF and encapsulated UDP packets.`,
	PersistentPreRun: connectToServerRDB,
}

// region Init Module
func loadCobraCliConfigs() {
	AttachPayloadCommands(rootCmd)
	AttachLogCommands(rootCmd)
}

func main() {
	loadCobraCliConfigs()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
