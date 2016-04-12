package sshtun

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

const (
	sshhost = "blahsshhost.blah.org"
	sshport = 22
	sshuser = "blahuser"
	sshpass = "blahblah"
)

func TestSshConnection(t *testing.T) {
	l, err := NewLink(sshhost+":"+strconv.Itoa(sshport), sshuser, sshpass)
	if err != nil {
		t.Errorf("Error generating SSH link: %v", err)
		return
	}
	defer l.Close()

	fmt.Printf("Link struct value: %q\n", l)
}

func TestSshTunnel(t *testing.T) {
	l, err := NewLink(sshhost+":"+strconv.Itoa(sshport), sshuser, sshpass)
	if err != nil {
		t.Errorf("Error starting SSH link: %v", err)
		return
	}
	defer l.Close()

	tun, err := l.TunnelIn(2022, "spirilis.net", 22)
	if err != nil {
		t.Errorf("Error creating tunnel: %v", err)
		return
	}

	delay := time.After(time.Second * 30)
	failsafe := time.After(time.Second * 35)
	for {
		select {
		case <-tun.Closed:
			fmt.Println("Tunnel shut down.")
			return
		case <-delay:
			tun.Control <- "close"
			// this should cause t.Closed to trigger shortly after
		case <-failsafe:
			t.Errorf("Tunnel did not shut down after 30 seconds!!")
			return
		}
	}
}

func TestSshDeadConnection(t *testing.T) {
	l, err := NewLink(sshhost+":"+strconv.Itoa(sshport), sshuser, sshpass)
	if err != nil {
		t.Errorf("Error starting SSH link: %v", err)
		return
	}
	defer l.Close()

	png := time.NewTicker(time.Second * 5)
	k := time.After(time.Second * 25)

	for {
		select {
		case <-png.C:
			err := l.Check()
			if err != nil {
				fmt.Printf("Ssh Connection Check() failed with %v\n", err)
				return
			} else {
				fmt.Println("Ssh Connection Check() succeeded")
			}
		case <-k:
			l.Close()
		}
	}
}

func TestSshAutoRestart(t *testing.T) {
	l, err := NewLink(sshhost+":"+strconv.Itoa(sshport), sshuser, sshpass)
	if err != nil {
		t.Errorf("Error starting SSH link: %v", err)
		return
	}

	tb := NewTunnelBroker(l)
	err = tb.AddTunnel(2022, "spirilis.net", 22)
	if err != nil {
		t.Errorf("Error creating tunnel: %v", err)
		l.Close()
		return
	}
	ctrlchan, err := tb.MonitorLink()
	if err != nil {
		t.Errorf("Error issuing TunnelBroker.MonitorLink: %v", err)
		l.Close()
		return
	}
	// Once tb.MonitorLink has run, you should forget about the original Link object ("l" here).
	// This is because once the TunnelBroker doMonitor goroutine issues a reconnect after an SSH link
	// is lost, the Link object will change - tb.Sshcon always has the current link object.

	time.Sleep(time.Second * 5)
	fmt.Println("Issuing close on SSH link (we expect the TunnelBroker monitor to reconnect within 10 seconds)")
	tb.Lock()
	tb.Sshcon.Close()
	tb.Unlock()
	time.Sleep(time.Second * 15) // Connection monitor should run 10 seconds after we closed the connection
	if tb.Sshcon.Check() != nil {
		t.Errorf("SSH Link Connection Monitor never reconnected!")
	}
	ctrlchan <- "close"
	return
}
