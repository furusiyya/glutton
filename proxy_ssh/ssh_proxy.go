package ssh

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/lunixbochs/vtclean"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var logger *log.Logger

type sshProxy struct {
	config     *ssh.ServerConfig
	callbackFn func(c ssh.ConnMetadata) (*ssh.Client, error)
	wrapFn     func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error)
	closeFn    func(c ssh.ConnMetadata) error
	allowedReq string

	reader       map[string]*readSession
	publicIP     string
	downloadPath string
	sensorName   string
	logFile      *os.File
}

type readSession struct {
	io.ReadCloser
	buffer    bytes.Buffer
	delimiter []byte
	n         int // Number of bytes written to buffer

	/*FYP*/
	regExp   *regexp.Regexp
	queue    chan work
	done     chan int
	quit     chan int
	session  *Session
	logFile  *os.File
	cmdId    uint64
	downPath string
	logPath  string
}

func NewSSHProxy(logFile *os.File, l *log.Logger, dest, downloadPath, sensorName string) (ssh *sshProxy, err error) {
	ssh = &sshProxy{
		downloadPath: downloadPath,
		sensorName:   sensorName,
		logFile:      logFile,
	}
	logger = l
	err = ssh.initConf(dest)
	if err != nil {
		logger.Error(errors.Wrap(formatErrorMsg("Connection failed at SSH Proxy: ", err), "ssh.prxy"))
		return nil, err
	}
	return
}

func (s *sshProxy) initConf(dest string) error {

	rsaKey, err := s.sshKeyGen()
	if err != nil {
		logger.Error(errors.Wrap(err, "ssh.prxy"))
		return err
	}

	private, _ := ssh.ParsePrivateKey(rsaKey)

	s.allowedReq = "session pty-req env shell exit-status"

	s.reader = make(map[string]*readSession)

	var sessions map[net.Addr]map[string]interface{} = make(map[net.Addr]map[string]interface{})
	conf := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			logger.Infof("[prxy.ssh] logging attempt: %s, user %s password: %s\n", c.RemoteAddr(), c.User(), string(pass))
			sessions[c.RemoteAddr()] = map[string]interface{}{
				"username": c.User(),
				"password": string(pass),
			}

			clientConfig := &ssh.ClientConfig{
				User: "admin",
				Auth: []ssh.AuthMethod{
					ssh.Password("123456"),
				},
			}

			client, err := ssh.Dial("tcp", dest, clientConfig)
			if err != nil {
				/*FYP*/
				s.reader[c.RemoteAddr().String()].queue <- work{
					user:   c.User(),
					pass:   string(pass),
					status: false,
					typ:    auth,
					client: string(c.ClientVersion()),
				}
				s.reader[c.RemoteAddr().String()].done <- 1
			} else {
				s.reader[c.RemoteAddr().String()].queue <- work{
					user:   c.User(),
					pass:   string(pass),
					status: true,
					typ:    auth,
					client: string(c.ClientVersion()),
				}
				s.reader[c.RemoteAddr().String()].done <- 1
				/*FYP*/
			}
			sessions[c.RemoteAddr()]["client"] = client
			return nil, err
		},
		ServerVersion: "SSH-2.0-OpenSSH-Alpine-Linux-2.0",
	}

	conf.AddHostKey(private)

	s.config = conf

	s.callbackFn = func(c ssh.ConnMetadata) (*ssh.Client, error) {
		meta, _ := sessions[c.RemoteAddr()]
		logger.Infof("[prxy.ssh] %v", meta)
		client := meta["client"].(*ssh.Client)
		logger.Infof("[prxy.ssh] Connection accepted from: %s\n", c.RemoteAddr())
		return client, nil
	}
	s.wrapFn = func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error) {
		s.reader[c.RemoteAddr().String()].ReadCloser = r
		return s.reader[c.RemoteAddr().String()], nil
	}
	s.closeFn = func(c ssh.ConnMetadata) error {
		logger.Infof("[prxy.ssh] Connection closed.")
		return nil
	}

	return nil
}

func (s *sshProxy) Start(listen string) (err error) {

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Fatalf("net.Listen failed: %v\n", err)
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Fatalf("listen.Accept failed: %v\n", err)
			return err
		}

		go func() {
			if err := s.handle(conn); err != nil {
				logger.Errorf("Error occurred while serving %s\n", err)
				return
			}
		}()
	}
}

func (s *sshProxy) handle(conn net.Conn) error {
	/*FYP*/
	srcIP, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())

	destIP, destPort, _ := net.SplitHostPort(conn.LocalAddr().String())
	s.publicIP = destIP

	s.reader[conn.RemoteAddr().String()] = &readSession{
		delimiter: []byte("\n"),
		// FYP
		regExp:   parser(),
		done:     make(chan int, 1),
		queue:    make(chan work, 1),
		quit:     make(chan int, 1),
		cmdId:    0,
		downPath: s.downloadPath,
		logFile:  s.logFile,
	}

	go s.reader[conn.RemoteAddr().String()].dispatcher(conn.RemoteAddr().String())
	/*FYP*/

	/*FYP*/
	s.reader[conn.RemoteAddr().String()].session = &Session{
		Id:        uint64(time.Now().UnixNano()),
		SensorId:  s.sensorName,
		TimeStamp: time.Now().UTC(),
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     destIP,
		Service:   "ssh",
		DstPort:   destPort,
		EventType: "Session",
		Status:    "opened",
	}
	s.reader[conn.RemoteAddr().String()].produceJSON(s.reader[conn.RemoteAddr().String()].session)
	defer func() {
		s.reader[conn.RemoteAddr().String()].session.TimeStamp = time.Now().UTC()
		s.reader[conn.RemoteAddr().String()].session.Status = "closed"
		s.reader[conn.RemoteAddr().String()].produceJSON(s.reader[conn.RemoteAddr().String()].session)
		s.reader[conn.RemoteAddr().String()].quit <- 1
		delete(s.reader, conn.RemoteAddr().String())
	}()

	/*FYP*/

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	defer conn.Close()
	if err != nil {
		logger.Error(errors.Wrap(formatErrorMsg("Failed to handshake", err), "ssh.prxy"))
		return (err)
	}

	/* FYP */

	clientConn, err := s.callbackFn(serverConn)
	defer clientConn.Close()
	if err != nil {
		logger.Error(errors.Wrap(err, "ssh.prxy"))
		return (err)
	}

	go ssh.DiscardRequests(reqs)

	for ch := range chans {

		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "Request not allowed")
			logger.Errorf("[prxy.ssh] Invalid channel type requested: %v", ch.ChannelType())
			continue
		}

		sshClientChan, clientReq, err := clientConn.OpenChannel(ch.ChannelType(), ch.ExtraData())
		if err != nil {
			logger.Error(errors.Wrap(formatErrorMsg(" Could not accept client channel: ", err), "ssh.prxy"))
			return err
		}

		sshServerChan, serverReq, err := ch.Accept()
		if err != nil {
			logger.Error(errors.Wrap(formatErrorMsg(" Could not accept server channel: ", err), "ssh.prxy"))
			return err
		}

		// Connect requests of ssh server and client
		go func(conn net.Conn) {
			logger.Debug("[prxy.ssh] Waiting for request")

		r:
			for {
				var req *ssh.Request
				var dst ssh.Channel

				select {
				case req = <-serverReq:
					logger.Debug("1", req)
					dst = sshClientChan
				case req = <-clientReq:
					logger.Debug("2", req)
					dst = sshServerChan
				}

				// Check if connection is closed
				if req == nil {
					logger.Debug("[prxy.ssh] SSH Request is nil")
					return
				}

				if !strings.Contains(s.allowedReq, req.Type) {
					ch.Reject(ssh.UnknownChannelType, "request not allowed")
					logger.Error("[ssh.prxy] Invalid request type ", req.Type)
					continue
				}

				logger.Debugf("[prxy.ssh] Request: \n\n%s %s %s %s\n\n", dst, req.Type, req.WantReply, req.Payload)
				b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if err != nil {
					logger.Error(errors.Wrap(err, "ssh.prxy"))
				}

				if req.WantReply {
					logger.Debug("3", b)
					req.Reply(b, nil)
				}

				switch req.Type {
				case "exit-status":
					break r
				case "exec":
					logger.Debug("[prxy.ssh] SSH request 'EXEC' is not supported\n\n[prxy.ssh] SSH request 'EXEC' is not supported")
					conn.Close()
					return
				default:
					logger.Errorf("[prxy.ssh] %s", req.Type)
				}
			}

			sshServerChan.Close()
			sshClientChan.Close()
		}(conn)

		var wrappedServerChan io.ReadCloser = sshServerChan
		var wrappedClientChan io.ReadCloser = sshClientChan

		defer wrappedServerChan.Close()
		defer wrappedClientChan.Close()

		if s.wrapFn != nil {
			wrappedClientChan, err = s.wrapFn(serverConn, sshClientChan)
		}

		go io.Copy(sshClientChan, wrappedServerChan)
		go io.Copy(sshServerChan, wrappedClientChan)

	}

	if s.closeFn != nil {
		s.closeFn(serverConn)
	}

	return nil
}

// TODO: Use of existing key
func (s *sshProxy) sshKeyGen() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		logger.Error(errors.Wrap(err, "ssh.prxy"))
		return nil, err
	}
	err = priv.Validate()
	if err != nil {
		logger.Error(errors.Wrap(formatErrorMsg("Validation failed.", err), "ssh.prxy"))
		return nil, err
	}

	priv_der := x509.MarshalPKCS1PrivateKey(priv)

	priv_blk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   priv_der,
	}

	RSA_Key := pem.EncodeToMemory(&priv_blk)

	// Shot to validating private bytes
	_, err = ssh.ParsePrivateKey(RSA_Key)
	if err != nil {
		logger.Error(errors.Wrap(err, "ssh.prxy"))
		return nil, err
	}
	return RSA_Key, nil
}

func formatErrorMsg(msg string, err error) error {
	return errors.New(fmt.Sprintf("%s  %s\n", msg, err))
}

func (rs *readSession) Read(p []byte) (n int, err error) {
	n, err = rs.ReadCloser.Read(p)

	if bytes.Contains(p[:n], rs.delimiter) {
		rs.buffer.Write(p[:n])
		go rs.collector((rs.n + n))
		rs.n = 0
	} else {
		rs.buffer.Write(p[:n])
		rs.n += n
	}
	return n, err
}

func (rs *readSession) collector(n int) {

	b := rs.buffer.Next(n)
	if len(b) != n {
		log.Error(errors.Wrap(formatErrorMsg("Logging is not working properly.", nil), "ssh.prxy"))
	}
	if n > 2 {
		// Clean up raw terminal output by stripping escape sequences
		sanitized := vtclean.Clean(string(b[:]), false)
		lines := strings.Split(sanitized, "\n")
		for _, line := range lines {
			match := rs.regExp.FindStringSubmatch(line)
			if len(match) != 0 {
				if len(strings.TrimSpace(match[4])) > 0 {
					rs.queue <- work{
						matches: match,
						typ:     headerWithCommand,
					}
					rs.done <- 1
				} else {
					rs.queue <- work{
						matches: match,
						typ:     header,
					}
					rs.done <- 1
				}
				continue
			}
			if rs.cmdId != 0 {
				rs.queue <- work{
					data: line,
					typ:  response,
				}
				rs.done <- 1
			} else {
				rs.queue <- work{
					data: line,
					typ:  outofBound,
				}
				rs.done <- 1
			}

		}
	} else {
		log.Info("10 Expected: %v", b[:])
	}
	b = nil
	return
}

func (rs *readSession) String() string {
	return rs.buffer.String()
}

func (rs *readSession) Close() error {
	return rs.ReadCloser.Close()
}
