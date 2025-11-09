package main

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// region Helper Functions
// Helper function
func getFileNameFromString(fileName string) (result string) {
	return fileName[strings.LastIndex(fileName, "/")+1:] // Returns either everything after the final /, or, the whole string
}

// LPush to the command log
func LPushUserCommandLog(command string) {
	rdbEntry := fmt.Sprintf("cmdLog:user:%02d", UserId)
	rdb.LPush(context.Background(), rdbEntry, command)
}

// Push a command to the command stack itself
func LPushUserCommand(command string) {
	rdb.LPush(context.Background(), "commandstack", command)
	LPushUserCommandLog(command)
}

// Returns nothing, will open vim to a temporary file if no file exists at the filepath.
func checkOrCreateFile(filePath string) (returnPath string) {
	// Check if file exists, if not open vim to create it
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		returnPath := fmt.Sprintf("/tmp/%s", filePath)
		vimCmd := exec.Command("vim", returnPath)
		vimCmd.Stdin = os.Stdin
		vimCmd.Stdout = os.Stdout
		vimCmd.Stderr = os.Stderr

		err := vimCmd.Run()
		if err != nil {
			fmt.Printf("Error running vim: %v\n", err)
			os.Exit(1)
		}

		return returnPath
	}

	return filePath
}

// Add a users script to the redis database so it can be referenced in commands
func addUserScriptToRdb(filePath string) {
	// Userdata
	hashTable := fmt.Sprintf("user:%02d", UserId)
	fieldName := fmt.Sprintf("script:%s", getFileNameFromString(filePath))

	// If the user wrote a script, this will check for it, otherwise,
	filePath = checkOrCreateFile(filePath)

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

	rdb.HSet(context.Background(), hashTable, fieldName, marshaledData) // If someone pushes an overlapping script, this will over write the value
}
