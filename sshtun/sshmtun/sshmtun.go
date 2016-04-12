// Executable utility - sshmtun will run an SSH tunnel daemon
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"spirilis/sshtun"
	"time"
)

var server, user, password string

func init() {
	flag.StringVar(&server, "host", "", "Remote SSH server to connect")
	flag.StringVar(&user, "u", "", "Username for SSH server")
	flag.StringVar(&password, "p", "", "Password for SSH server")
}

func parseStdinJSON(totalNeeded int) {
	dec := json.NewDecoder(os.Stdin)

	// read open brace
	t, err := dec.Token()
	if err != nil {
		log.Fatalf("Stdin JSON error: %v\n", err)
	}
	ts, ok := t.(json.Delim)
	if !ok || ts != '{' {
		log.Fatalf("Stdin JSON error: Opening character token isn't a brace")
	}
	fmt.Println("got opening brace")

	for dec.More() {
		var t, ts interface{}
		t, err = dec.Token()
		ts, ok = t.(string)
		if !ok {
			var ts interface{}
			ts, ok = t.(json.Delim)
			if !ok || (ok && ts != '}') {
				log.Fatalf("Stdin JSON error: Closing character isn't a brace")
			}
			return
		}

		if ts == "Host" && dec.More() {
			fmt.Println("saw Host")
			t, err = dec.Token()
			ts, ok = t.(string)
			if ok {
				fmt.Println("got host")
				server = ts.(string)
				totalNeeded--
			}
		}

		if ts == "Username" && dec.More() {
			fmt.Println("saw Username")
			t, err = dec.Token()
			ts, ok = t.(string)
			if ok {
				fmt.Println("got user")
				user = ts.(string)
				totalNeeded--
			}
		}

		if ts == "Password" && dec.More() {
			fmt.Println("saw Password")
			t, err = dec.Token()
			ts, ok = t.(string)
			if ok {
				fmt.Println("got password")
				password = ts.(string)
				totalNeeded--
			}
		}

		if totalNeeded == 0 {
			break
		}
	}
}

func main() {
	flag.Parse()
	var totalParamsNeeded int
	if user == "" {
		totalParamsNeeded++
	}
	if password == "" {
		totalParamsNeeded++
	}
	if server == "" {
		totalParamsNeeded++
	}
	if totalParamsNeeded > 0 {
		fmt.Printf("%d parameters missing from command line options; reading JSON from stdin\n", totalParamsNeeded)
		parseStdinJSON(totalParamsNeeded)
	}

	// Start SSH link
	fmt.Printf("Creating SSH link for server=%s, user=%s ...\n", server, user)
	l, err := sshtun.NewLink(server, user, password)
	if err != nil {
		log.Fatalf("Error connecting (server=%s, user=%s) via SSH: %v\n", server, user, err)
	}
	tb := sshtun.NewTunnelBroker(l)
	err = tb.AddTunnel(10022, "localhost", 22)
	if err != nil {
		log.Fatalf("Error creating tunnel: %v\n", err)
	}
	fmt.Println("Created SSH tunnel; remote port 10022 to localhost:22")
	_, err = tb.MonitorLink()
	if err != nil {
		log.Fatalf("Error creating background monitor for SSH link: %v\n", err)
	}
	fmt.Println("Autonomously monitoring SSH link.")
	for {
		time.Sleep(time.Second * 5)
	}
}
