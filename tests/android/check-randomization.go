package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
)

type payload struct {
	Version    int    `json:"v"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ct"`
}

func extractPayload(path, requiredKey string) (payload, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return payload{}, "", err
	}
	defer file.Close()
	decoder := xml.NewDecoder(io.LimitReader(file, 8*1024*1024))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return payload{}, "", fmt.Errorf("Invalid snapshot XML: %w", err)
		}
		element, ok := token.(xml.StartElement)
		if !ok || element.Name.Local != "string" {
			continue
		}
		key := ""
		for _, attribute := range element.Attr {
			if attribute.Name.Local == "name" {
				key = attribute.Value
			}
		}
		if requiredKey != "" && key != requiredKey {
			continue
		}
		var value string
		if err := decoder.DecodeElement(&value, &element); err != nil {
			return payload{}, "", err
		}
		var candidate payload
		if err := json.Unmarshal([]byte(value), &candidate); err != nil {
			continue
		}
		if candidate.Version == 1 && candidate.IV != "" && candidate.Ciphertext != "" {
			return candidate, key, nil
		}
	}
	return payload{}, "", fmt.Errorf("No matching secure-storage JSON payload found in %s", path)
}

func check(paths []string) (int, error) {
	if len(paths) < 2 {
		return 1, fmt.Errorf("Usage: go run check-randomization.go snapshot1.xml snapshot2.xml [snapshot3.xml ...]")
	}
	ivs := make(map[string]bool)
	ciphertexts := make(map[string]bool)
	key := ""
	for _, path := range paths {
		sample, selected, err := extractPayload(path, key)
		if err != nil {
			return 1, err
		}
		key = selected
		ivs[sample.IV] = true
		ciphertexts[sample.Ciphertext] = true
	}
	fmt.Printf("Samples: %d\nUnique IVs: %d\nUnique ciphertexts: %d\n", len(paths), len(ivs), len(ciphertexts))
	if len(ivs) != len(paths) || len(ciphertexts) != len(paths) {
		fmt.Println("FAIL: Duplicate IV or ciphertext detected.")
		return 2, nil
	}
	fmt.Println("PASS: Every snapshot has a unique IV and ciphertext.")
	return 0, nil
}

func main() {
	status, err := check(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(status)
}
