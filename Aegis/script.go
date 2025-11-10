package main

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// TODO:
// Add a script command "payload script [name]"
// which will either:
//   - Open the script in vim (if it exists), or
//   - Open vim to write a new script
var payloadScriptRoot = &cobra.Command{
	Use:   "script",
	Short: "Handle interactions with scripts you have written for payloads",
	Long:  "Opens a vim session to the name of the script you provide, if it is a file path it will open the file, otherwise, it will load from the redis database.",
}

var listScripts = &cobra.Command{
	Use:   "list",
	Short: "Lists scripts in the database for your user",
	Long:  "Lists all of the scripts that are currently stored in the database for your user",
	Run:   ListScript,
}

var newScript = &cobra.Command{
	Use:   "new [scriptname]",
	Short: "Creates a new script with the name you provide",
	Long:  "Opens a vim session to the name of the script you provide, if it is a file path it will open the file, otherwise, it will load from the redis database.",
	Args:  cobra.ExactArgs(1),
	Run:   WriteScriptToRedis,
}

var removeScript = &cobra.Command{
	Use:   "rm [scriptname]",
	Short: "Removes a script with the name you provide",
	Args:  cobra.ExactArgs(1),
	Run:   RemoveScript,
}

var editScript = &cobra.Command{
	Use:   "edit [scriptname]",
	Short: "Edits the contents of a script with the name you provide",
	Long:  "Edits the contents of a script with the name you provide, if it is a file path it will edit the file, otherwise, it will load from the redis database.",
	Args:  cobra.ExactArgs(1),
	Run:   EditScript,
}

var printScript = &cobra.Command{
	Use:   "print [scriptname]",
	Short: "Prints the contents of a script with the name you provide",
	Args:  cobra.ExactArgs(1),
	Run:   PrintScript,
}

func RemoveScript(cmd *cobra.Command, args []string) {
	hashTable := fmt.Sprintf("user:%02d:scripts", UserId)
	scriptName := fmt.Sprintf("path:%s", args[0])

	keyEntry, deletionError := rdb.HDel(context.Background(), hashTable, scriptName).Result()
	if deletionError != nil {
		fmt.Printf("Unable to delete key %s from %s: %v\n", scriptName, hashTable, deletionError)
	}

	if keyEntry == 0 {
		fmt.Printf("Key %s did not exist in table %s\n", args[0], hashTable)
	} else {
		fmt.Printf("Removed script %s from %s at index [%02d]\n", args[0], hashTable, keyEntry)
	}
}

func ListScript(cmd *cobra.Command, args []string) {
	hashTable := fmt.Sprintf("user:%02d:scripts", UserId)

	allEntries, HKeys := rdb.HKeys(context.Background(), hashTable).Result()
	if HKeys != nil {
		fmt.Printf("HGetAll Error: %v", HKeys)
	}

	if len(allEntries) >= 1 {
		fmt.Printf("%-10s %s\n", "INDEX", "SCRIPT NAME")
		for index, scriptName := range allEntries {
			parsedName := strings.Replace(scriptName, "path:", "", 1)
			fmt.Printf("%-10d %s\n", index, parsedName)
		}
	} else {
		fmt.Printf("NO ENTRIES IN %s\n", hashTable)
	}
}

func PrintScript(cmd *cobra.Command, args []string) {
	filePath := args[0] // This should really be file name, but im following a standard atp
	hashTable := fmt.Sprintf("user:%02d:scripts", UserId)
	fieldName := fmt.Sprintf("path:%s", filePath)

	//
	scriptContext, HGetError := rdb.HGet(context.Background(), hashTable, fieldName).Result()
	if HGetError != nil {
		fmt.Printf("HGetError for %s: %v\n", hashTable, HGetError)
	}

	// TODO: Use protobuffs instead of JSON one day
	var scriptData PayloadScript
	unmarshallError := json.Unmarshal([]byte(scriptContext), &scriptData)
	if unmarshallError != nil {
		fmt.Printf("Error unmarshaling data: %v\n", unmarshallError)
		os.Exit(1)
	}

	// Redis stores a b64 encoded string of any scripts users provide
	decodedString, decodingError := b64.StdEncoding.DecodeString(scriptData.EncodedData)
	if decodingError != nil {
		fmt.Printf("Error decoding b64 string: %v\n", decodingError)
		os.Exit(1)
	}

	fmt.Printf("%s\n", decodedString)
}

// TODO: When you push an existing script into redis, you can't edit it with this command, its just stuck as is.
func EditScript(cmd *cobra.Command, args []string) {
	filePath := args[0]

	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		hashTable := fmt.Sprintf("user:%02d:scripts", UserId)
		fieldName := fmt.Sprintf("path:%s", filePath)

		exists, HExistsError := rdb.HExists(context.Background(), hashTable, fieldName).Result()
		if HExistsError != nil {
			fmt.Printf("Error in rdb HExists command: %v\n", HExistsError)
			os.Exit(1)
		}

		if exists {
			scriptContext, HGetError := rdb.HGet(context.Background(), hashTable, fieldName).Result()
			if HGetError != nil {
				fmt.Printf("Error in rdb HGet command: %v\n", HGetError)
				os.Exit(1)
			}

			tempFilePath := createTemporaryPayloadScript([]byte(scriptContext)) // Script context will come back as a string but really thats cap
			openFileInVim(tempFilePath)                                         // This blocks till user is done writing in file
			fileCleanupError := addUserScriptToRdb(filePath, tempFilePath)
			if fileCleanupError != nil {
				fmt.Printf("Failed to remove file: %v", fileCleanupError)
			}
		} else {
			fmt.Printf("Script '%s' does not exist in the database for user %02d.\n", filePath, UserId)
			os.Exit(1)
		}
	}
}

func WriteScriptToRedis(cmd *cobra.Command, args []string) {
	filePath := args[0]
	fileName := getFileNameFromString(filePath)
	hashTable := fmt.Sprintf("user:%02d:scripts", UserId)
	fieldName := fmt.Sprintf("path:%s", filePath)

	exists, HExistsError := rdb.HExists(context.Background(), hashTable, fieldName).Result()
	if HExistsError != nil {
		fmt.Printf("Error in rdb HExists command: %v\n", HExistsError)
		os.Exit(1)
	}

	if !(exists) {
		fileCleanupError := addUserScriptToRdb(fileName, filePath)
		if fileCleanupError != nil {
			fmt.Printf("Failed to remove file: %v", fileCleanupError)
		}
	} else {
		fmt.Printf("Script '%s' already exists in the database for user %02d.\n", fileName, UserId)
		os.Exit(1)
	}
}

func AttachScriptCommands(rootCmd *cobra.Command) {
	// Script Payloads Commands
	payloadScriptRoot.AddCommand(listScripts)
	payloadScriptRoot.AddCommand(newScript)
	payloadScriptRoot.AddCommand(removeScript)
	payloadScriptRoot.AddCommand(printScript)
	payloadScriptRoot.AddCommand(editScript)

	rootCmd.AddCommand(payloadScriptRoot)
}
