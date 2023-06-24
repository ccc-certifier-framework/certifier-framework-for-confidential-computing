package main

import (
	"bytes"
	"fmt"
	"net"

	certlib "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certlib"
)

func client(conn net.Conn) bool {
	fmt.Printf("At client\n")
	b := []byte{5, 6, 7, 8, 9, 10}
	if !certlib.SizedSocketWrite(conn, b) {
		return false
	}
	nb := certlib.SizedSocketRead(conn)
	fmt.Printf("b : ")
	certlib.PrintBytes(b)
	fmt.Printf("\n")
	fmt.Printf("nb: ")
	certlib.PrintBytes(nb)
	fmt.Printf("\n")
	if !bytes.Equal(b, nb) {
		return false
	}
	return true
}

func Run() {
	serverAddr := "127.0.0.1:2021"
	fmt.Printf("\nClient looking for %s\n", serverAddr)

	// use ResolveTCPAddr to create address to connect to
	raddr, err := net.ResolveTCPAddr("tcp", serverAddr)
	if err != nil {
		fmt.Printf("net.ResolveTCPAddr failed\n")
		return
	}
	// DialTCP creates connection to remote address.
	fmt.Printf("Dialing %s\n", serverAddr)
	conn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		fmt.Printf("Main: failed to connect to server\n")
		return
	}
	defer conn.Close()

	if !client(conn) {
		fmt.Printf("Test failed\n")
	} else {
		fmt.Printf("Test succeeded\n")
	}
	return
}

func main() {

	Run()
}
