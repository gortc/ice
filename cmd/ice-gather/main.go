// Command gathers local addresses and prints them.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/gortc/ice"
	"github.com/gortc/ice/candidate"
)

func main() {
	addrs, err := ice.Gather()
	if err != nil {
		log.Fatal("failed to gather: ", err)
	}
	for _, a := range addrs {
		if !ice.IsHostIPValid(a.IP, false) {
			continue
		}
		fmt.Printf("%s\n", a)
		laddr, err := net.ResolveUDPAddr("udp",
			a.ZeroPortAddr(),
		)
		if err != nil {
			log.Fatal(err)
		}
		c, err := net.ListenUDP("udp", laddr)
		if err != nil {
			fmt.Println("   ", "failed:", err)
			continue
		}
		listenAddr := c.LocalAddr().(*net.UDPAddr)
		addr := ice.Addr{
			IP:    listenAddr.IP,
			Port:  listenAddr.Port,
			Proto: candidate.UDP,
		}
		ct := &ice.Candidate{
			Addr: addr,
			Base: addr,
			Type: candidate.Host,
		}
		ct.Foundation = ice.Foundation(ct, ice.Addr{})
		fmt.Println("   ", "bind ok", c.LocalAddr(), "0x"+hex.EncodeToString(ct.Foundation))
		_ = c.Close()
	}
}
