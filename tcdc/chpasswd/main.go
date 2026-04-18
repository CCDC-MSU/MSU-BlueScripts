package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var passwords = map[string]string{
	"alice":   "IzCJp7K8q8txysOIvhZE",
	"bob":     "rfU5AWlthqh3YegDP0cP",
	"craig":   "YiRvDsUc0HS8ZQLRv9VK",
	"chad":    "2Iu8HMjMLiOsHelI1S6t",
	"trudy":   "lWTdOCX7faDkkGMsRp5d",
	"mallory": "fVtUzBF4iA2oY60hhLoM",
	"mike":    "HxhqKmtyNmO7iIyFHdak",
	"yves":    "VYTRidvCYUxTVu4WIg3J",
	"judy":    "64sYSnvvjIl9R9aKgR9Q",
	"sybil":   "k637BI7LCMZWzHjtVQal",
	"walter":  "imsDjSgV6DJIeV48SvIE",
	"wendy":   "pPweC24I2PGcOc31Iucm",
}

var users = []string{
	"alice", "bob", "craig", "chad", "trudy", "mallory",
	"mike", "yves", "judy", "sybil", "walter", "wendy",
}

func main() {
	hostname, _ := os.Hostname()
	fmt.Printf("=== Changing passwords on %s ===\n", hostname)

	var lines []string
	fmt.Println("\nNew credentials:")
	fmt.Println(strings.Repeat("-", 40))

	for _, user := range users {
		pw := passwords[user]
		lines = append(lines, fmt.Sprintf("%s:%s", user, pw))
		fmt.Printf("%-12s %s\n", user, pw)
	}

	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: %v (are you root?)\n", err)
		os.Exit(1)
	}

	// Set up SSH key for root
	fmt.Println("\n=== Setting up root SSH key ===")
	sshDir := "/root/.ssh"
	authKeys := filepath.Join(sshDir, "authorized_keys")
	authKeysOld := filepath.Join(sshDir, "authorized_keys.old")

	os.MkdirAll(sshDir, 0700)

	if _, err := os.Stat(authKeys); err == nil {
		if err := os.Rename(authKeys, authKeysOld); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR moving old authorized_keys: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Moved authorized_keys -> authorized_keys.old")
	}

	pubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAp4nTGAVb9Vbofl4AymPVL3sDkpnWP85ulroMrgb47Z tcdc_test\n"
	if err := os.WriteFile(authKeys, []byte(pubKey), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR writing authorized_keys: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Wrote new authorized_keys with tcdc_test key")

	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("Done.")
}
