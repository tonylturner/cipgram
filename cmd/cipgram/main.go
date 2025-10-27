package main

import (
	"fmt"
	"log"
	"os"

	"cipgram/pkg/cli"
	"cipgram/pkg/logging"
)

func main() {
	// Initialize logging from environment variables
	logging.SetLogLevel()

	// Create and run the CLI application
	app, err := cli.NewApp()
	if err != nil {
		log.Printf("❌ Error: %v", err)
		cli.PrintUsageExamples()
		os.Exit(1)
	}

	if err := app.Run(); err != nil {
		log.Printf("❌ Error: %v", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Analysis complete!\n")
}
