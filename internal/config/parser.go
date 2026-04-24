package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

type Config struct {
	IsServer bool
	IsClient bool
	Port     int
	Address  string
	Input    string
	Output   string
	Timeout  int
}

// ParseArgs parses the command line arguments and returns a Config struct.
// It will os.Exit(0) if -h or --help is provided.
func ParseArgs(args []string) (*Config, error) {
	fs := flag.NewFlagSet("ipk-rdt", flag.ContinueOnError)

	// Keep outputs silent to easily intercept ErrHelp and usage
	fs.SetOutput(io.Discard)

	cfg := &Config{}
	
	fs.BoolVar(&cfg.IsServer, "s", false, "Start in server mode")
	fs.BoolVar(&cfg.IsClient, "c", false, "Start in client mode")
	fs.IntVar(&cfg.Port, "p", 0, "UDP port number")
	fs.StringVar(&cfg.Address, "a", "", "Address (listen address for server, destination for client)")
	fs.StringVar(&cfg.Input, "i", "-", "Input file (client only)")
	fs.StringVar(&cfg.Output, "o", "-", "Output file (server only)")
	fs.IntVar(&cfg.Timeout, "w", 1, "Timeout in seconds")

	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stdout)
			fmt.Fprintf(os.Stdout, "Usage of ipk-rdt:\n")
			fs.PrintDefaults()
			os.Exit(0)
		}
		return nil, fmt.Errorf("error parsing arguments: %w", err)
	}

	if cfg.IsServer && cfg.IsClient {
		return nil, errors.New("cannot specify both -c and -s")
	}
	if !cfg.IsServer && !cfg.IsClient {
		return nil, errors.New("exactly one of -c or -s MUST be specified")
	}

	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, errors.New("a valid port (-p) MUST be specified (1-65535)")
	}

	if cfg.IsClient {
		if cfg.Address == "" {
			return nil, errors.New("-a HOST MUST be specified in client mode")
		}
	}

	if cfg.Timeout <= 0 {
		return nil, errors.New("timeout (-w) MUST be positive")
	}

	return cfg, nil
}
