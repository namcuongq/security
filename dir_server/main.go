package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: dir_server <dir> <listen>")
		os.Exit(1)
	}

	dir := os.Args[1]
	listen := os.Args[2]
	http.Handle("/", http.FileServer(http.Dir(dir)))
	panic(http.ListenAndServe(listen, nil))
}
