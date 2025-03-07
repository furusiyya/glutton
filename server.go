package glutton

import (
	"errors"
	"fmt"
	"net"

	"github.com/seud0nym/tproxy-go/tproxy"
)

type Server struct {
	tcpListener net.Listener
	udpConn     *net.UDPConn
	tcpPort     uint
	udpPort     uint
}

func NewServer(tcpPort, udpPort uint) *Server {
	s := &Server{
		tcpPort: tcpPort,
		udpPort: udpPort,
	}
	return s
}

func (s *Server) Start() error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", s.tcpPort))
	if err != nil {
		return err
	}
	if s.tcpListener, err = tproxy.ListenTCP("tcp4", tcpAddr); err != nil {
		return err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", s.udpPort))
	if err != nil {
		return err
	}
	if s.udpConn, err = tproxy.ListenUDP("udp4", udpAddr); err != nil {
		return err
	}
	if s.udpConn == nil {
		return errors.New("nil udp listener")
	}
	return nil
}
