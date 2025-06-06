package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: tamper <JWT>")
		os.Exit(1)
	}

	original := os.Args[1]
	parts := strings.Split(original, ".")
	if len(parts) != 3 {
		fmt.Println("Invalid JWT format")
		os.Exit(1)
	}

	// Decode payload (second part)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("Error decoding payload: %v\n", err)
		os.Exit(1)
	}

	// Parse payload into map
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		fmt.Printf("Error unmarshalling payload: %v\n", err)
		os.Exit(1)
	}

	// Modify "exp" to be 1 hour in the future
	newExp := time.Now().Add(6 * time.Hour).Unix()
	fmt.Printf("Original exp: %v\n", payload["exp"])
	payload["exp"] = newExp
	fmt.Printf("Tampered exp: %v\n", newExp)

	// Re-encode modified payload
	newPayloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshalling modified payload: %v\n", err)
		os.Exit(1)
	}
	newPayloadB64 := base64.RawURLEncoding.EncodeToString(newPayloadBytes)

	// Construct a tampered token (with original header and signature)
	tampered := parts[0] + "." + newPayloadB64 + "." + parts[2]
	fmt.Println("\nTampered JWT (invalid signature):")
	fmt.Println(tampered)
}
