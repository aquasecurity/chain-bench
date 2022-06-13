package main

import (
	"os"

	"github.com/aquasecurity/chain-bench/internal/commands"
)

var version = "dev"

func main() {
	if err := commands.Execute(version); err != nil {
		os.Exit(1)
	}
}
