// Package sshtun / file sshconn.go: SSH I/O primitives for sshtun including connecting to remote SSH server and handling tunnel connections
package sshtun

import (
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"strconv"
	"strings"
)

// Link is a handle to a live SSH link
type Link struct {
	conn                 *ssh.Client
	SSHHost              string
	SSHUser, SSHPassword string
}

// Tun is a handle to a TCP tunnel over Link
type Tun struct {
	LocalPort, RemotePort uint16
	LocalHost             string
	Closed                chan struct{}
	Control               chan string
}

// SSHConnectError is self explanatory.
const SSHConnectError TunnelError = "SSH connect error"

// NewLink establishes a new SSH link
func NewLink(hostname string, username string, password string) (*Link, error) {
	link := new(Link)
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
	}

	var hn string
	if strings.Contains(hostname, ":") {
		hn = hostname
	} else {
		hn = hostname + ":22"
	}
	conn, err := ssh.Dial("tcp", hn, sshConfig) // returns *ssh.Client
	if err != nil {
		return nil, SSHConnectError.Append("host=" + hostname + ", user=" + username + " - " + err.Error())
	}

	link.conn = conn
	link.SSHHost = hostname
	link.SSHUser = username
	link.SSHPassword = password
	return link, nil
}

// Close will gracefully close the SSH connection
func (l *Link) Close() {
	l.conn.Close()
}

// Check will attempt to start an undifferentiated SSH protocol session within our connection to validate the connection is still available.
// Used by the TunnelBroker Link monitor to detect SSH connection failure for reconnect purposes.
func (l *Link) Check() error {
	sess, err := l.conn.NewSession()
	if err != nil {
		return err
	}
	sess.Close()
	return nil
}

// StartTunnelOnNilConnection denotes a bug whereby a tunnel creation operation was attempted on a null ssh connection
const StartTunnelOnNilConnection TunnelError = "Link.TunnelIn called with a nil ssh.Conn value"

// ListenFailed would be an odd scenario but potential with SSH link down
const ListenFailed TunnelError = "Create listener failed"

// TunnelIn establishes a new persistent tunnel that supports at most 1 connection.
func (l *Link) TunnelIn(rport uint16, hostlocal string, lport uint16) (*Tun, error) {
	if l.conn == nil {
		return nil, StartTunnelOnNilConnection
	}

	tunnel := new(Tun)
	tunnel.RemotePort = rport
	tunnel.LocalHost = hostlocal
	tunnel.LocalPort = lport

	nl, err := l.conn.Listen("tcp", hostlocal+":"+strconv.FormatUint(uint64(rport), 10))
	if err != nil {
		return nil, ListenFailed.Append("remote " + strconv.FormatUint(uint64(rport), 10) + " to " + hostlocal + ":" + strconv.FormatUint(uint64(lport), 10) + " - " + err.Error())
	}

	// Set up channels, start handler goroutine
	tunnel.Closed = make(chan struct{})
	tunnel.Control = make(chan string, 10)
	go tunnelrunner(nl, hostlocal, lport, tunnel.Control, tunnel.Closed)

	return tunnel, nil
}

type acceptPair struct {
	conn net.Conn
	err  error
}

func tunnelrunner(lst net.Listener, outhost string, outport uint16, ctrlchan <-chan string, closenotify chan<- struct{}) {
	for {
		// Wait for incoming connection from remote SSH host
		var incon net.Conn
		ts := true
	looplistener:
		for {
			var chanacc chan acceptPair
			if ts {
				chanacc = make(chan acceptPair)
				go func(c chan<- acceptPair, listener net.Listener) {
					incon, err := listener.Accept()
					s := acceptPair{conn: incon, err: err}
					c <- s
					close(c)
					return
				}(chanacc, lst)
			}
			ts = false

			select {
			case i := <-chanacc:
				if i.err != nil {
					// Tear down the tunnel; something's wrong
					close(closenotify)
					return
				}
				incon = i.conn
				break looplistener // break out of the for{} loop
			case ctrl := <-ctrlchan:
				switch ctrl {
				case "close": // Tear down tunnel entirely (quits this goroutine)
					close(closenotify)
					return
				}
			}
		}

		// Construct our outhost:outport connection and launch goroutines to marshal data between them
		log.Printf("Issuing net.Dial(tcp, %s)\n", outhost+":"+strconv.FormatUint(uint64(outport), 10))
		outcon, err := net.Dial("tcp", outhost+":"+strconv.FormatUint(uint64(outport), 10))
		if err != nil {
			log.Println("net.Dial failed")
			// Tear down remote-SSH tunnel connection so they see something's wrong, then continue the master for loop.
			incon.Close()
			continue
		}

		// Construct goroutines to alert for incoming data or connection closures
		inconData := make(chan []byte, 10)
		inconResponse := make(chan struct{}) // flow control
		inconClosed := make(chan struct{})
		outconData := make(chan []byte, 10)
		outconResponse := make(chan struct{}) // flow control
		outconClosed := make(chan struct{})

		go connreader(incon, inconData, inconResponse, inconClosed)
		go connreader(outcon, outconData, outconResponse, outconClosed)

		connup := true
		for connup {
			select {
			case <-inconClosed:
				outcon.Close()
				connup = false
			case <-outconClosed:
				incon.Close()
				connup = false
			case b := <-inconData:
				_, err := outcon.Write(b)
				inconResponse <- struct{}{} // signal ready for more data
				if err != nil {             // Connection down, close it out
					incon.Close() // we must signal inconResponse before this or else we leak goroutines from connreader waiting on the response chan
					connup = false
				}
			case b := <-outconData:
				_, err := incon.Write(b)
				outconResponse <- struct{}{} // signal ready for more data
				if err != nil {
					outcon.Close()
					connup = false
				}
			case ctrl := <-ctrlchan:
				// Parse control channel command grammar
				switch ctrl {
				case "kill": // Kill individual link (has no effect during accept)
					outcon.Close()
					incon.Close()
					connup = false
				case "close": // Tear down tunnel entirely (quits this goroutine)
					outcon.Close()
					incon.Close()
					close(closenotify)
					return
				}
			} // select chan's
		} // for connup == true
	} // for loop while we have this listener intact
}

func connreader(c net.Conn, sendto chan<- []byte, response <-chan struct{}, closenotify chan<- struct{}) {
	buf := make([]byte, 32768, 32768) // should be large enough for any jumbo frames MTU

	for {
		buf = buf[:32768]
		len, err := c.Read(buf)
		if err != nil { // Pretty much *any* error here results in failure of the connection...
			log.Printf("connreader error: %v\n", err)
			close(closenotify)
			return
		}
		buf = buf[:len] // resize the slice len to the actual read size
		sendto <- buf
		<-response // wait for main thread to consume
	}
}
