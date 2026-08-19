package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mihanistudio/mihanisecurity/internal/service"
)

func main() {
	mode := flag.String("mode", "", "install | uninstall | run")
	flag.Parse()
	switch *mode {
	case "-install":
		*mode = "install"
	case "-uninstall":
		*mode = "uninstall"
	case "-run":
		*mode = "run"
	}
	if err := service.Run(*mode); err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		os.Exit(1)
	}
}
