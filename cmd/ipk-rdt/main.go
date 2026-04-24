package main

import (
	"fmt"
	"os"

	"ipk-rdt/internal/app"
	"ipk-rdt/internal/config"
)

func main() {
	cfg, err := config.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.IsServer {
		var out *os.File
		if cfg.Output == "-" {
			out = os.Stdout
		} else {
			out, err = os.Create(cfg.Output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer out.Close()
		}

		err = app.RunServer(cfg, out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}

	} else if cfg.IsClient {
		var in *os.File
		if cfg.Input == "-" {
			in = os.Stdin
		} else {
			in, err = os.Open(cfg.Input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
				os.Exit(1)
			}
			defer in.Close()
		}

		err = app.RunClient(cfg, in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Client error: %v\n", err)
			os.Exit(1)
		}
	}
}
