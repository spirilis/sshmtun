// Package sshtun / file sshmgmt.go: Management I/O channel for creating new tunnels and shutting down existing ones
package sshtun

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// SSHMgmtDefaultMonitorInterval is a constant used for the automatic SSH link reconnect feature (*TunnelBroker.MonitorLink())
const SSHMgmtDefaultMonitorInterval = 15
const defaultReconTimeoutInterval = 120
const defaultReconRetryAgainInterval = 600

// TunnelBroker is a registry of Tun's managed by another program or library
type TunnelBroker struct {
	Sshcon               *Link
	mu                   sync.Mutex
	Tunnels              []*Tun
	ReconTimeoutInterval uint
	ReconRetryInterval   uint
}

// TunnelError is an error type specific to this sshtun package
type TunnelError string

func (t TunnelError) Error() string { return string(t) }

// Append will construct a new TunnelError by appending the included text
func (t TunnelError) Append(s string) TunnelError { return t + TunnelError(": ") + TunnelError(s) }

// PortAlreadyInUse is typically used when a tunnel is requested for a remote port where we already
// have a configured tunnel
const PortAlreadyInUse TunnelError = "Remote Port Already Has a Tunnel"

// TunnelNotFound only applies during CloseTunnel since its arguments include the set of rport/lhost/lport used for lookup
const TunnelNotFound TunnelError = "Tunnel Request failed due to Tunnel Not Found"

// NewTunnelBroker creates a new tunnel broker out of an existing SSH link
func NewTunnelBroker(l *Link) *TunnelBroker {
	if l == nil {
		log.Fatalln("NewTunnelBroker() called with a nil Link pointer!")
		return nil // never reaches here
	}
	t := new(TunnelBroker)
	t.Sshcon = l
	t.ReconTimeoutInterval = defaultReconTimeoutInterval
	t.ReconRetryInterval = defaultReconRetryAgainInterval
	return t
}

// Lock the tunnel broker mutex in case we want to dig into the Sshcon
func (tb *TunnelBroker) Lock() {
	tb.mu.Lock()
}

// Unlock tunnel broker Sshcon (matches Lock())
func (tb *TunnelBroker) Unlock() {
	tb.mu.Unlock()
}

// AddTunnel adds a new tunnel to a TunnelBroker registry.  This should be run primarily by
// the TunnelBroker's REST API manager.
func (tb *TunnelBroker) AddTunnel(rport uint16, lhost string, lport uint16) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	for i := range tb.Tunnels {
		if tb.Tunnels[i].RemotePort == rport {
			return PortAlreadyInUse
		}
	}

	tptr, err := tb.Sshcon.TunnelIn(rport, lhost, lport)
	if err != nil {
		return err
	}

	tb.Tunnels = append(tb.Tunnels, tptr)
	return nil
}

// CloseAll aborts all tunnels along with the SSH link
func (tb *TunnelBroker) CloseAll() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	for i := range tb.Tunnels {
		tb.Tunnels[i].Control <- "close"
	}
	tb.Tunnels = []*Tun{}
	tb.Sshcon.Close()
}

// CloseTunnel will find a tunnel with the specified parameters, and remove it.
// Compatible with REST APIs since it resolves the Tun object (out of Tunnels) for us.
func (tb *TunnelBroker) CloseTunnel(rport uint16, lhost string, lport uint16) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	found := false
	var tptr *Tun
	var i int // declared in func scope since we use it at the bottom
	for i = range tb.Tunnels {
		tptr = tb.Tunnels[i]
		if tptr.RemotePort == rport && tptr.LocalHost == lhost && tptr.LocalPort == lport {
			found = true
			break
		}
	}
	if !found {
		return TunnelNotFound
	}

	tptr.Control <- "close"
	// remove tptr entry from tb.Tunnels
	tb.Tunnels = tb.Tunnels[:i+copy(tb.Tunnels[i:], tb.Tunnels[i+1:])]
	return nil
}

// ReattachTunnels takes an old set of *Tun's and re-creates them onto a new SSH link.
func (tb *TunnelBroker) ReattachTunnels(newlink *Link) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	var collection []*Tun
	for _, tun := range tb.Tunnels {
		var (
			lport, rport uint16
			lhost        string
		)
		lport = tun.LocalPort
		lhost = tun.LocalHost
		rport = tun.RemotePort

		newtun, err := newlink.TunnelIn(rport, lhost, lport)
		if err == nil {
			collection = append(collection, newtun)
		}
	}

	tb.Tunnels = collection
}

// MonitorLink spawns a goroutine which autonomously watches an SSH link and reconnects/reattaches tunnels as
// needed.  Returned is a control channel where you may shut down the link and with mutex protection, you can
// use the TunnelBroker methods to add new tunnels directly under the hood.
func (tb *TunnelBroker) MonitorLink() (chan<- string, error) {
	tb.mu.Lock()
	if err := tb.Sshcon.Check(); err != nil {
		return nil, err
	}
	tb.mu.Unlock()
	ctrl := make(chan string, 2)
	go tb.doMonitor(ctrl)
	return ctrl, nil
}

func (tb *TunnelBroker) doMonitor(ctrl <-chan string) {
	tck := time.NewTicker(time.Second * SSHMgmtDefaultMonitorInterval)
	recon := make(chan struct{}, 2) // buffered (2) to prevent locking of the goroutine when writing to the chan
	var isRecon, isReconRetry bool
	var reconTimeout int
	reconComplete := make(chan struct{})

	for {
		select {
		case c := <-ctrl:
			switch c {
			case "close":
				// Tear down the whole tunnel, SSH link, monitor goroutine
				tb.CloseAll()
				return
			case "reset":
				// Bounce the SSH link, killing any current tunnel connections in the process, but not wrecking the tunnel config.
				// Reconnection happens within this goroutine's for/select loop after tck.C ticks.
				tb.mu.Lock()
				if err := tb.Sshcon.Check(); err == nil {
					tb.Sshcon.Close()
				}
				tb.mu.Unlock()
			}
		case <-tck.C:
			if isRecon {
				reconTimeout++
				var intvl int
				if intvl = int(tb.ReconTimeoutInterval) / SSHMgmtDefaultMonitorInterval; intvl < 1 {
					intvl = 2
				}
				if isReconRetry && reconTimeout > tb.ReconRetryInterval {
					fmt.Println("Attempting reconnect again-")
					isReconRetry = false
					reconComplete = make(chan struct{}) // reconComplete was lost by hung goroutine, create anew
					recon <- struct{}{}
				}
				if reconTimeout > intvl {
					// It's hanging indefinitely; ignore it and try again after the refractory timeout
					if !isReconRetry {
						fmt.Printf("Timed out reconnecting, waiting refractory period (%d sec) before retrying-\n", tb.ReconRetryInterval)
					}
					isReconRetry = true
				}
				break
			}
			tb.mu.Lock()
			err := tb.Sshcon.Check()
			tb.mu.Unlock()
			if err != nil {
				// Connection lost; reconnect?
				fmt.Println("Connection found in failed state; signaling reconnect")
				recon <- struct{}{} // trigger case <-recon:
			}
			// not 100% sure why I chose to use a signaling channel within the same goroutine to trigger reconnect... but it works ;)
		case <-recon:
			fmt.Println("Issuing reconnect")
			// NewLink can hang, so we broke this out into a goroutine
			isRecon = true
			isReconRetry = false
			reconTimeout = 0
			go tb.doReconnect(reconComplete)
		case <-reconComplete:
			isRecon = false
			isReconRetry = false
			reconTimeout = 0
			reconComplete = make(chan struct{}) // reconComplete was consumed, so we create a new one
		}
	}
}

func (tb *TunnelBroker) doReconnect(alertChan chan struct{}) {
	tb.mu.Lock()
	sshhost := tb.Sshcon.SSHHost
	sshuser := tb.Sshcon.SSHUser
	sshpass := tb.Sshcon.SSHPassword
	tb.mu.Unlock()

	link, err := NewLink(sshhost, sshuser, sshpass)
	if err == nil {
		tb.ReattachTunnels(link)
		tb.mu.Lock()
		tb.Sshcon = link
		tb.mu.Unlock()
	}
	close(alertChan)
}
