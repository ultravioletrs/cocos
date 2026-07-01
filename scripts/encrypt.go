package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: go run encrypt.go <key_file> <input_file> <output_file>")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	inputFile := os.Args[2]
	outputFile := os.Args[3]

	// Read key
	key, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("Failed to read key file: %v\n", err)
		os.Exit(1)
	}
	if len(key) != 32 {
		fmt.Printf("Key must be 32 bytes, got %d\n", len(key))
		os.Exit(1)
	}

	// Read plaintext
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Failed to read input file: %v\n", err)
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Failed to create cipher: %v\n", err)
		os.Exit(1)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Failed to create GCM: %v\n", err)
		os.Exit(1)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("Failed to generate nonce: %v\n", err)
		os.Exit(1)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Combine nonce + ciphertext + tag
	// Seal returns ciphertext || tag, so we just append it to nonce
	output := append(nonce, ciphertext...)

	err = os.WriteFile(outputFile, output, 0644)
	if err != nil {
		fmt.Printf("Failed to write output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully encrypted %s to %s\n", inputFile, outputFile)
}
