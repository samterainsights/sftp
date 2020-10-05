package main

// small wrapper around sftp server that allows it to be used as a separate process subsystem call by the ssh server.
// in practice this will statically link; however this allows unit testing from the sftp client.

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/tera-insights/sftp"
	"golang.org/x/crypto/ssh"
)

const rsaPrvPem = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAmzH/FK39mm9tmMThhPeDUGS/dVp16I91TrCHPSRmosesZCRJMSSq
qE7Wd++4LD2KpfGNsgGg7imeYZPyisJBugXBXWPkt5Ufkcr4LlRFKUchcg5DUxqUazUAck
OlO88bCuDdNpdMlBbtMkLqYrJkxe/JjEOAp6UkhStvjGKyTFsPOnUfdqVOtw6sAQEPEtoC
g9XR2hzTEAO3xxkrOlZ1bzHDFDicWJLbH52xXuHUkb6fbLRFBMBZc/AwAHe8aFaD+OA+XZ
rk0JTBMtmcOF1YeJADf0k39YrEkhLk9CmcjVgwcjV1rwDBriqK4Riavnl5bMFhBVrMtSHH
sjcAHchkMwAAA9hhTms4YU5rOAAAAAdzc2gtcnNhAAABAQCbMf8Urf2ab22YxOGE94NQZL
91WnXoj3VOsIc9JGaix6xkJEkxJKqoTtZ377gsPYql8Y2yAaDuKZ5hk/KKwkG6BcFdY+S3
lR+RyvguVEUpRyFyDkNTGpRrNQByQ6U7zxsK4N02l0yUFu0yQupismTF78mMQ4CnpSSFK2
+MYrJMWw86dR92pU63DqwBAQ8S2gKD1dHaHNMQA7fHGSs6VnVvMcMUOJxYktsfnbFe4dSR
vp9stEUEwFlz8DAAd7xoVoP44D5dmuTQlMEy2Zw4XVh4kAN/STf1isSSEuT0KZyNWDByNX
WvAMGuKorhGJq+eXlswWEFWsy1IceyNwAdyGQzAAAAAwEAAQAAAQAbF8pRIOLCACvg3JYG
MXOCKGRoJ0eoNssi1px1ZxJn3nXQ8ai5ZI5KXaEBRR8g0gmPWLEE31Xp3eghXsObx7fTss
eD9zlpdyYQvJ9A70M3poxHLghAzMYWRSVzzS1eWJR+/KyBqD4dKDd2a8ohOsVu7KKB0xL1
sVXDzcZmeqBnxcQzoj6jVF/ZCP5+VvEJHCcdHhCSXbQE7E5KYzDQXt5iyh1nHYzIVlZ//a
nOWhw6UhJcKftQ7egLzWx96n1mFRqRkgxgaFsyqolHTdoUqXZihItkjOrHMvmxuosBM/qS
bwdvV+Ts5v4zp5lwOfoBDtOIvjttTfHm8RVmVbu9V5e5AAAAgQDG3LxiDHmokOIoR7FizA
/Gw0mpHRJHJ5tyO9FVjmKkq53ME3FhLpzn+LxuPRzN6FL1oyTmkas9CE14U9kU2Xi5adYf
3u/SjYFrV24xFB514QWWVaov9CYu7NOyGwyQunqXa4E4yg1wglxsdZ3/Avqhut/7vWdl6p
/NRjbBMFDgoAAAAIEAyl7iXLwmjjHQi8l7vLLRnWsW6LGbpxv+5Ahboi37bIwcN2zcE6D3
3adJlDb/0SL9kUYyM10giMutu11kWMkeFdaA8yBbkyK/wyB0sghMorh9sR47GdOD6cNb2P
NgsDBW0Qog0cy3NNqPafUwOClqWjkXvPn0YV5co/jumNjJnkcAAACBAMRSq0GEv514lOMI
ymjRF8MRg7B4lLgq4HCED4PpY7jP61zzWawYfUdkUjGyQX/xjjmTiXyoPu3Ru8rSCuySEx
2LXhB+MAAkP/6AJNg7IQsL+K5oehhm8whCUyU/nbiN7XBb5qE5zOSXgmbChp7iSAKMV7g8
3UYyp/Q7tSXAeqS1AAAAImNsYXVzX3NhbUBTYW1zLU1hY0Jvb2stUHJvLTIubG9jYWw=
-----END OPENSSH PRIVATE KEY-----
`

func fatal(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	os.Exit(1)
}

func main() {
	var port uint

	flag.UintVar(&port, "port", 4200, "Local TCP port to serve on")
	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fatal("Failed to listen on %s: %v\n", addr, err)
	}

	fmt.Printf("Listening on %s...\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fatal("Failed to accept TCP connection: %v", err)
		}

		go handleConn(conn)
	}
}

func handleConn(c net.Conn) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	prvKey, _ := ssh.ParsePrivateKey([]byte(rsaPrvPem))
	config.AddHostKey(prvKey)

	// Perform an SSH handshake
	conn, chans, reqs, err := ssh.NewServerConn(c, config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer conn.Close() // TODO: check error and log (maybe?)

	log.Printf("SSH handshake successful [user: %s, client-version: %s]", conn.User(), conn.ClientVersion())

	// We don't want out-of-band requests, but we must service the [Go] channel
	// or the connection will hang
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		log.Printf("Incoming SSH channel: %s", newChannel.ChannelType())

		// At the SSH application level, we only care about "session" channels,
		// which SFTP is served through
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			log.Printf("Unknown channel type: %s\n", newChannel.ChannelType())
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Failed to accept channel: %v", err)
			continue
		}
		log.Println("Channel accepted")

		go filterNonSFTP(requests)

		log.Printf("serving sftp")
		if err = sftp.Serve(channel, sftp.MemFS()); err == io.EOF {
			log.Println("SFTP client killed session")

			if err = channel.Close(); err != nil {
				log.Printf("Failed to gracefully close SSH connection: %v", err)
			}
		} else if err != nil {
			log.Printf("SFTP disconnected unexpectedly: %v", err)
		}
	}
}

// filterNonSFTP lets through SFTP subsystem requests and rejects everything else.
func filterNonSFTP(in <-chan *ssh.Request) {
	for req := range in {
		switch req.Type {
		case "subsystem":
			log.Printf("Got 'subsystem' request: %s", req.Payload)
			if string(req.Payload[4:]) == "sftp" {
				req.Reply(true, nil)
				continue
			}
			fallthrough
		default:
			log.Printf("Rejecting request [type: %s, payload: %s]", req.Type, req.Payload)
			req.Reply(false, nil)
		}
	}
}
