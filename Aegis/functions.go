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

	"github.com/google/uuid"
)

// Types
type PayloadScript struct {
	FilePath    string `json:"file_path"`
	EncodedData string `json:"encoded_data"`
}

// region Helper Functions
// Helper function
func getFileNameFromString(fileName string) (result string) {
	return fileName[strings.LastIndex(fileName, "/")+1:] // Returns either everything after the final /, or, the whole string
}

// LPush to the command log
func LPushUserCommandLog(command string) {
	rdbEntry := fmt.Sprintf("cmdLog:user:%02d", UserId)
	rdb.RPush(context.Background(), rdbEntry, command) // Push to the back so we can get an accurate count of command history
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
		tempFileIdentifier := uuid.New()
		returnPath = fmt.Sprintf("/tmp/%s", tempFileIdentifier.String())
		openFileInVim(returnPath)

		return returnPath
	}

	return filePath
}

// Add a users script to the redis database so it can be referenced in commands
func addUserScriptToRdb(scriptName string, filePath string) (fileCleanup error) {
	// Userdata
	hashTable := fmt.Sprintf("user:%02d:scripts", UserId)
	fieldName := fmt.Sprintf("path:%s", scriptName)

	// If the user wrote a script, this will check for it, otherwise,
	filePath = checkOrCreateFile(filePath)
	if strings.Contains(filePath, "/tmp/") {
		defer func() {
			fileCleanup = os.Remove(filePath)
		}() // Anonymous function to catch file cleanup errors
	}

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
		os.Exit(1)
	}

	_, HSetError := rdb.HSet(context.Background(), hashTable, fieldName, marshaledData).Result() // If someone pushes an overlapping script, this will over write the value
	if HSetError != nil {
		fmt.Printf("Failure to HSet to table %s for field %s: %v", hashTable, fieldName, HSetError)
		os.Exit(1)
	}
	return nil // No error if we got to this point
}

func createTemporaryPayloadScript(encodedData []byte) string {
	var scriptData PayloadScript

	// TODO: Use protobuffs instead of JSON one day
	unmarshallError := json.Unmarshal(encodedData, &scriptData)
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

	// We want our users to be able to edit with vim, so we need a file.
	tempFileIdentifier := uuid.New()
	tempFilePath := fmt.Sprintf("/tmp/%s", tempFileIdentifier.String())
	tempFile, fileCreationError := os.Create(tempFilePath)
	if fileCreationError != nil {
		fmt.Printf("Error creating file %s: %v\n", tempFilePath, fileCreationError)
		os.Exit(1)
	}
	defer tempFile.Close()

	// Move the decoded strings bytes into the file
	_, fileWriteError := tempFile.Write(decodedString)
	if fileWriteError != nil {
		fmt.Printf("Error writing to file %s: %v\n", tempFilePath, fileWriteError)
		os.Exit(1)
	}
	tempFile.Sync()

	return tempFilePath
}

func openFileInVim(filePath string) {
	vimCmd := exec.Command("vim", filePath)
	vimCmd.Stdin = os.Stdin
	vimCmd.Stdout = os.Stdout
	vimCmd.Stderr = os.Stderr

	err := vimCmd.Run()
	if err != nil {
		fmt.Printf("Error running vim: %v\n", err)
		os.Exit(1)
	}
}
