package main

import (
	"fmt"
	"net"

	certlib "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certlib"
)

func service(conn net.Conn) {
	fmt.Printf("At service\n")
	b := certlib.SizedSocketRead(conn)
	if !certlib.SizedSocketWrite(conn, b) {
		return
	}
	conn.Close()
	return
}

func Run() {
	serverAddr := "127.0.0.1:2021"
	fmt.Printf("\nServer Addres: %s\n", serverAddr)

	// Listen for clients.
	fmt.Printf("Listening\n")
	sock, err := net.Listen("tcp", serverAddr)
	if err != nil {
		fmt.Printf("listen error\n")
		return
	}

	// Service client connections.
	for {
		fmt.Printf("server: at accept\n")
		conn, err := sock.Accept()
		if err != nil {
			fmt.Printf("Can't accept connection: %s\n", err.Error())
			continue
		}
		fmt.Printf("Accepted connection\n")
		go service(conn)
	}
}

func main() {

	Run()
}
