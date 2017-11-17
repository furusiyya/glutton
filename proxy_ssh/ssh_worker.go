package ssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Unknwon/com"
	"github.com/pkg/errors"
)

type inputType int

const (
	header inputType = iota
	headerWithCommand
	response
	auth
	download
	outofBound
)

const (
	commandRe     = `(?P<user>\S+):(?P<path>(?:~|/).*)(?P<status>\$|#)\s(?P<command>.*)(?:\n|$)`
	sniffDownload = `wget|curl|\.com|http|ftp|torrent|\d+\.\d+\.\d+\.\d+`

	binaryRe = `\A\w+\z`
	joinsRe  = `&|<|;|>|\|`
	urlRe    = `\A\w+[\$-_\.\+!\*'\(\),-~'/:]+\S+\z`
	savedRe  = `-\s‘(?P<name>.+)’\ssaved\s`
)

type work struct {
	matches []string
	data    string
	typ     inputType // Indicates whether the data contains command response or not

	user, pass, client string
	status             bool
}

type Session struct {
	Id        uint64    `json:"sessionId"`
	SensorId  string    `json:"eventSource"`
	TimeStamp time.Time `json:"timeStamp"`
	SrcIP     string    `json:"srcIP"`
	SrcPort   string    `json:"srcPort"`
	DstIP     string    `json:"dstIP"`
	DstPort   string    `json:"dstPort"`
	Service   string    `json:"service"`
	EventType string    `json:"eventType"`
	Status    string    `json:"status"`
}

type Auths struct {
	Id        uint64    `json:"sessionId"`
	SensorId  string    `json:"eventSource"`
	TimeStamp time.Time `json:"timeStamp"`
	SrcIP     string    `json:"srcIP"`
	SrcPort   string    `json:"srcPort"`
	DstIP     string    `json:"dstIP"`
	DstPort   string    `json:"dstPort"`
	Service   string    `json:"service"`
	EventType string    `json:"eventType"`
	User      string    `json:"userName"`
	Pass      string    `json:"password"`
	Client    string    `json:"client"`
	Success   bool      `json:"success"`
}

type Input struct {
	Id        uint64    `json:"sessionId"`
	SensorId  string    `json:"eventSource"`
	TimeStamp time.Time `json:"timeStamp"`
	SrcIP     string    `json:"srcIP"`
	SrcPort   string    `json:"srcPort"`
	DstIP     string    `json:"dstIP"`
	DstPort   string    `json:"dstPort"`
	Service   string    `json:"service"`
	EventType string    `json:"eventType"`
	User      string    `json:"user"`
	Path      string    `json:"executionPath"`
	Privilege uint8     `json:"privilege"`
	CommandId uint64    `json:"commandId"`
	Command   string    `json:"command"`
}

type Response struct {
	Id        uint64    `json:"sessionId"`
	SensorId  string    `json:"eventSource"`
	TimeStamp time.Time `json:"timeStamp"`
	SrcIP     string    `json:"srcIP"`
	SrcPort   string    `json:"srcPort"`
	DstIP     string    `json:"dstIP"`
	DstPort   string    `json:"dstPort"`
	Service   string    `json:"service"`
	EventType string    `json:"eventType"`
	CommandId uint64    `json:"parentId"`
	Response  string    `json:"response"`
}

type Downloads struct {
	Id        uint64    `json:"sessionId"`
	SensorId  string    `json:"eventSource"`
	TimeStamp time.Time `json:"timeStamp"`
	SrcIP     string    `json:"srcIP"`
	SrcPort   string    `json:"srcPort"`
	DstIP     string    `json:"dstIP"`
	DstPort   string    `json:"dstPort"`
	Service   string    `json:"service"`
	EventType string    `json:"eventType"`
	CommandId uint64    `json:"commandId"`
	FileHash  string    `json:"fileHash"`
	URL       string    `json:"url"`
	binaries  string    `json:"binary"`
	arguments string    `json:"args"`
	Comments  string    `json:"downloaderComments"`
}

type OutofBound struct {
	Id        uint64    `json:"sessionId"`
	SensorId  string    `json:"eventSource"`
	TimeStamp time.Time `json:"timeStamp"`
	SrcIP     string    `json:"srcIP"`
	SrcPort   string    `json:"srcPort"`
	DstIP     string    `json:"dstIP"`
	DstPort   string    `json:"dstPort"`
	Service   string    `json:"service"`
	EventType string    `json:"eventType"`
	Data      string    `json:"input"`
}

type TTY struct {
	Id     uint64
	Buffer bytes.Buffer
}

func (rs *readSession) dispatcher(remoteAddr string) {
	snifDown := regexp.MustCompile(sniffDownload)
	var onlyHeaders *Input
	var prvlg uint8 = 1 // 1 indicate non root user
	for {
		select {
		case <-rs.done:
			w := <-rs.queue
			switch w.typ {

			case auth:
				a := &Auths{
					Id:        rs.session.Id,
					SensorId:  rs.session.SensorId,
					TimeStamp: time.Now().UTC(),
					SrcIP:     rs.session.SrcIP,
					SrcPort:   rs.session.SrcPort,
					DstIP:     rs.session.DstIP,
					DstPort:   rs.session.DstPort,
					Service:   "ssh",
					EventType: "Auth",
					User:      w.user,
					Pass:      w.pass,
					Client:    w.client,
					Success:   w.status,
				}
				rs.produceJSON(a)
				break
			case header:
				if w.matches[3] == "#" {
					prvlg = 0
				}
				rs.cmdId = uint64(time.Now().UnixNano())
				onlyHeaders = &Input{
					Id:        rs.session.Id,
					SensorId:  rs.session.SensorId,
					SrcIP:     rs.session.SrcIP,
					SrcPort:   rs.session.SrcPort,
					DstIP:     rs.session.DstIP,
					DstPort:   rs.session.DstPort,
					Service:   "ssh",
					EventType: "Command",
					User:      w.matches[1],
					Path:      w.matches[2],
					Privilege: prvlg,
					CommandId: rs.cmdId,
				}
				break

			case headerWithCommand:
				if w.matches[3] == "#" {
					prvlg = 0
				}
				rs.cmdId = uint64(time.Now().UnixNano())
				onlyHeaders = &Input{}
				i := &Input{
					Id:        rs.session.Id,
					SensorId:  rs.session.SensorId,
					TimeStamp: time.Now().UTC(),
					SrcIP:     rs.session.SrcIP,
					SrcPort:   rs.session.SrcPort,
					DstIP:     rs.session.DstIP,
					DstPort:   rs.session.DstPort,
					Service:   "ssh",
					EventType: "Command",
					User:      w.matches[1],
					Path:      w.matches[2],
					Privilege: prvlg,
					CommandId: rs.cmdId,
					Command:   w.matches[4],
				}
				if len(snifDown.FindStringSubmatch(w.matches[4])) > 0 {
					go rs.captureFiles(w.matches[4])
				}
				rs.produceJSON(i)
				break

			case response:
				if onlyHeaders.Id != 0 {
					onlyHeaders.TimeStamp = time.Now().UTC()
					onlyHeaders.Command = w.data
					if len(snifDown.FindStringSubmatch(w.data)) > 0 {
						go rs.captureFiles(w.data)
					}
					rs.produceJSON(onlyHeaders)
					onlyHeaders = &Input{}
					break
				} else {
					if len(w.data) == 0 {
						break
					}
					r := &Response{
						Id:        rs.session.Id,
						SensorId:  rs.session.SensorId,
						TimeStamp: time.Now().UTC(),
						SrcIP:     rs.session.SrcIP,
						SrcPort:   rs.session.SrcPort,
						DstIP:     rs.session.DstIP,
						DstPort:   rs.session.DstPort,
						Service:   "ssh",
						EventType: "Response",

						CommandId: rs.cmdId,
						Response:  w.data,
					}
					rs.produceJSON(r)
				}
				break
			case outofBound:
				r := &OutofBound{
					Id:        rs.session.Id,
					SensorId:  rs.session.SensorId,
					TimeStamp: time.Now().UTC(),
					SrcIP:     rs.session.SrcIP,
					SrcPort:   rs.session.SrcPort,
					DstIP:     rs.session.DstIP,
					DstPort:   rs.session.DstPort,
					Service:   "ssh",
					EventType: "stdouts",
					Data:      w.data,
				}
				rs.produceJSON(r)
				break
			}
		case <-rs.quit:
			return
		}
	}
	fmt.Println("000")
}

func (rs *readSession) produceJSON(event interface{}) {
	var (
		data []byte
		err  error
	)
	switch event.(type) {
	case *Session:
		data, err = json.Marshal(event.(*Session))
		if err != nil {
			return
		}
		break
	case *Auths:
		data, err = json.Marshal(event.(*Auths))
		if err != nil {
			return
		}
		break
	case *Input:
		data, err = json.Marshal(event.(*Input))
		if err != nil {
			return
		}
		break
	case *Response:
		data, err = json.Marshal(event.(*Response))
		if err != nil {
			return
		}
	case *Downloads:
		data, err = json.Marshal(event.(*Downloads))
		if err != nil {
			return
		}
		break
	case *OutofBound:
		data, err = json.Marshal(event.(*OutofBound))
		if err != nil {
			return
		}
		break
	}
	d := string(data)
	go rs.LogJSON(d)
}

func (rs *readSession) LogJSON(data string) {
	_, err := rs.logFile.WriteString(data + "\n")
	if err != nil {
		logger.Errorf("[ssh.prxy] JSON to file writing: %v", err)
	}
}

func parser() *regexp.Regexp {
	return regexp.MustCompile(commandRe)

}

func (rs *readSession) captureFiles(cmnd string) {
	dowloadEvent := &Downloads{
		Id:        rs.session.Id,
		SensorId:  rs.session.SensorId,
		TimeStamp: time.Now().UTC(),
		SrcIP:     rs.session.SrcIP,
		SrcPort:   rs.session.SrcPort,
		DstIP:     rs.session.DstIP,
		DstPort:   rs.session.DstPort,
		Service:   "ssh",
		EventType: "Download",
		CommandId: rs.cmdId,
	}

	binaries := regexp.MustCompile(binaryRe)
	joins := regexp.MustCompile(joinsRe)
	url := regexp.MustCompile(urlRe)
	commands := joins.Split(cmnd, -1)

	var urls string
	for _, command := range commands {
		sanitized := strings.TrimSpace(command)
		segments := strings.Split(sanitized, " ")
		for _, segment := range segments {
			if len(segment) < 1 {
				continue
			}
			expectedBinaries := binaries.FindStringSubmatch(segment)
			if len(expectedBinaries) > 0 {
				if dowloadEvent.binaries == "" {
					dowloadEvent.binaries += segment
					continue
				}
				dowloadEvent.binaries += ", " + segment
				continue
			}
			if segment[0] == '-' {
				if dowloadEvent.arguments == "" {
					dowloadEvent.arguments += segment
					continue
				}
				dowloadEvent.arguments += ", " + segment
				continue
			}
			expectedURL := url.FindStringSubmatch(segment)
			if len(expectedURL) > 0 {
				urls += "," + segment
				continue
			}
			logger.Errorf("[ssh.prxy] Error, no match: %v", segment)
		}
	}

	for _, v := range strings.Split(urls, ",") {
		if len(v) < 4 {
			continue
		}
		if !downloadFile(dowloadEvent, v, rs.downPath) {
			continue
		}
		dowloadEvent.URL = v
		rs.produceJSON(dowloadEvent)
	}
	return
}

func downloadFile(downEvent *Downloads, url string, downPath string) bool {
	saved := regexp.MustCompile(savedRe)

	fname := strconv.Itoa(int(time.Now().UnixNano()))
	path := downPath + fname

	stdout, stderr, err := com.ExecCmd("wget", url, "-O", path)
	if err != nil {
		logger.Errorf("[ssh.prxy] File downloading could not start: %v", err)
		downEvent.Comments = stderr

		os.Remove(path)
		return true
	} else if strings.Contains(stderr, "error:") || strings.Contains(stderr, "Error:") {
		downEvent.Comments = "Downloading Error! Check manually"

		os.Remove(path)
		return true
	} else {
		success := saved.FindStringSubmatch(stderr)
		if len(success) > 0 {
			downEvent.Comments = "Download Successfully"
			logger.Info("[ssh.prxy] Download successfully")
		} else {
			downEvent.Comments = stderr
		}
	}

	var hash []string
	stdout, stderr, err = com.ExecCmd("md5sum", path)
	if err != nil {
		logger.Errorf("[ssh.prxy] md5sum could not started: %v", err)
		downEvent.FileHash = "Error: Unable to execute hash command"
		downEvent.Comments = "Error in saving, check url manually"

		os.Remove(path)
		return true
	} else if len(stderr) != 0 {
		downEvent.FileHash = stderr
		downEvent.Comments = "Error in saving, check url manually"

		logger.Errorf("[ssh.prxy] md5sum Error: %v", stderr)
		os.Remove(path)
		return true
	} else if len(strings.Split(stdout, " ")) > 2 {
		hash = strings.Split(stdout, " ")
		downEvent.FileHash = hash[0]
	} else {
		downEvent.FileHash = stdout
		downEvent.Comments = "Error in saving, check url manually"
	}

	if com.IsExist(downPath + hash[0]) {
		logger.Infof("[ssh.prxy] File already exist %v", downPath+hash[0])
		if err := os.Remove(path); err != nil {
			logger.Errorf("[ssh.prxy] Error in removing %v , Error: %v", path, err)
		}
		os.Remove(path)
		return false
	}

	logger.Infof("[ssh.prxy] Renaming %v -> %v", path, downPath+hash[0])
	if !rename(path, downPath+hash[0]) {
		downEvent.FileHash = "nil"
		downEvent.Comments = "Rename: Error in saving, check url manually"
	}
	return true
}

func rename(old, nw string) bool {
	_, stderr, err := com.ExecCmd("mv", old, nw)
	if err != nil {
		logger.Errorf("[ssh.prxy] Rename could not started: %v", err)
		return false
	} else if len(stderr) != 0 {
		logger.Errorf("[ssh.prxy] Rename Error:: %v", stderr)
		return false
	} else {
		return true
	}
	return true
}

func ValidatePath(path string) error {
	if com.IsExist(path) {
		return nil
	} else {
		_, stderr, err := com.ExecCmd("mkdir", "-p", path)
		if err != nil {
			return err
		}
		if stderr != "" {
			return errors.New(stderr)
		}
	}
	return nil
}
