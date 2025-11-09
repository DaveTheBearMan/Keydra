package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// region CLI
var payloadRoot = &cobra.Command{
	Use:   "payload",
	Short: "Operations for Keydra payloads",
}

var payloadHistory = &cobra.Command{
	Use:   "history",
	Short: "Read from your users command history",
	Long:  "Shows all of the scripts and commands you have queued up in a payload",
	Run:   GetUserCommandHistory,
}

var payloadShow = &cobra.Command{
	Use:   "show",
	Short: "See information about your payload",
	Long:  "Allows you to review the current command buffer to clients",
}

// TODO:
// Add a script command "payload script [name]"
// which will either:
//   - Open the script in vim (if it exists), or
//   - Open vim to write a new script
var payloadScriptRoot = &cobra.Command{
	Use:   "script [scriptname]",
	Short: "Handle interactions with scripts you have written for payloads",
	Long:  "Opens a vim session to the name of the script you provide, if it is a file path it will open the file, otherwise, it will load from the redis database.",
}

var pushPayloadCommandSubCmd = &cobra.Command{
	Use:   "command [command]",
	Short: "Push a command onto the payload",
	Long:  "Pushes a command onto the Keydra command payload in Redis.",
	Args:  cobra.ExactArgs(1),
	Run:   pushPayloadCommandFunc,
}

var pushPayloadScriptSubCmd = &cobra.Command{
	Use:   "script [filepath]",
	Short: "Push a script onto the payload",
	Long:  "Pushes a script onto the Keydra command payload in Redis.",
	Args:  cobra.ExactArgs(1),
	Run:   pushPayloadScript,
}

// region CLI CMD
// Push a command onto the payload
func pushPayloadScript(cmd *cobra.Command, args []string) {
	// I chose a hash because I want to be able to assign data to the user, including scripts, keybinds, etc without having a stack that was pushed or popped from
	filePath := args[0]
	fileName := getFileNameFromString(filePath)
	hashTable := fmt.Sprintf("user:%02d", UserId)
	fieldName := fmt.Sprintf("script:%s", fileName)

	// Check if the scripts already been loaded into memory
	exists, HExistsError := rdb.HExists(context.Background(), hashTable, fieldName).Result()
	if HExistsError != nil {
		fmt.Printf("Error in rdb HExists command: %v\n", HExistsError)
		os.Exit(1)
	}

	// If the script does not yet exist in the users scripts, then we need to add it before pushing the reference to it into the stack of commands
	if !(exists) {
		addUserScriptToRdb(filePath)
	}

	// Push the users command onto a stack
	// "commandstack" is where commands are stored
	scriptPath := fmt.Sprintf("./aegis/%02d/%s", UserId, fileName)
	LPushUserCommand(scriptPath)
}

// Push a command (Basically just a wrapper)
func pushPayloadCommandFunc(cmd *cobra.Command, args []string) {
	// Command
	command := args[0]

	LPushUserCommand(command)
}

func GetUserCommandHistory(cmd *cobra.Command, args []string) {
	rdbEntry := fmt.Sprintf("cmdLog:user:%02d", UserId)

	// Only argument is the number of logs you want, -1 for all
	count, strconvErr := cmd.Flags().GetInt64("count")
	if strconvErr != nil {
		fmt.Printf("Error converting from ascii to int: %v", strconvErr)
		os.Exit(1)
	}

	historyLength, LLenErr := rdb.LLen(context.Background(), rdbEntry).Result()
	if LLenErr != nil {
		fmt.Printf("Failed to get length of list '%02d': %v\n", UserId, LLenErr)
		os.Exit(1)
	}

	var startIndex int64
	if count > historyLength {
		startIndex = 0
	} else {
		startIndex = historyLength - count
	}

	historyLog, LRangeErr := rdb.LRange(context.Background(), rdbEntry, startIndex, historyLength).Result()
	if LRangeErr != nil {
		fmt.Printf("Failed to read user log '%02d': %v\n", UserId, LRangeErr)
		os.Exit(1)
	}

	fmt.Printf("%-5s %s\n", "INDEX", "COMMAND")
	for i := range historyLog {
		entry := historyLog[i]

		fmt.Printf("%-5d %s\n", i+int(startIndex), entry)
	}
}

// Final Attach
func AttachPayloadCommands(rootCmd *cobra.Command) {
	// Push Payload Commands
	pushPayloadScriptSubCmd.Flags().Bool("save", false, "Save script (if a new one is created)")
	payloadHistory.Flags().Int64("count", 10, "How many commands to show (-1 for all)")

	// Attach to payload push
	payloadPushSubCmd.AddCommand(pushPayloadCommandSubCmd)
	payloadPushSubCmd.AddCommand(pushPayloadScriptSubCmd)

	// Payload Root Commands
	payloadRoot.AddCommand(payloadHistory)
	payloadRoot.AddCommand(payloadShow)
	payloadRoot.AddCommand(payloadPushSubCmd)

	// Attach to main
	rootCmd.AddCommand(payloadRoot)
}
