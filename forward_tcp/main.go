package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

var localServerHost = ""
var remoteServerHost = ""

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: forward_port [src] [dst]")
		os.Exit(1)
	}

	localServerHost = os.Args[1]
	remoteServerHost = os.Args[2]

	ln, err := net.Listen("tcp", localServerHost)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Port forwarding listening on", localServerHost)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleConnection(conn)
	}
}

func forward(src, dest net.Conn) {
	defer src.Close()
	defer dest.Close()
	_, err := io.Copy(src, dest)
	if err != nil {
		log.Println(err)
	}
}

func handleConnection(c net.Conn) {
	log.Println("Connection from: ", c.RemoteAddr(), "-->", remoteServerHost)
	remote, err := net.DialTimeout("tcp", remoteServerHost, 15*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	go forward(c, remote)
	go forward(remote, c)
}
