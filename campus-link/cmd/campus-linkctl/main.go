package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	path := flag.String("status", "/run/campus-link/status.json", "status JSON path")
	flag.Parse()
	b, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(b)
}
