package main

import (
	"fmt"
	"os"

	"ipk-rdt/internal/config"
)

func main() {
	cfg, err := config.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.IsServer {
		fmt.Fprintf(os.Stderr, "Server mode running on port %d...\n", cfg.Port)
		// TODO: initialize and start server
	} else if cfg.IsClient {
		fmt.Fprintf(os.Stderr, "Client mode connecting to %s:%d...\n", cfg.Address, cfg.Port)
		// TODO: initialize and start client
	}
}
