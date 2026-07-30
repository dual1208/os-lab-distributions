package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/edge"
)

var version = "dev"

func main() {
	path := flag.String("config", "/etc/campus-link/edge.json", "edge configuration")
	checkConfig := flag.Bool("check-config", false, "validate configuration and credentials without starting")
	flag.Parse()
	var cfg config.Edge
	if err := config.Load(*path, &cfg); err != nil {
		log.Fatal(err)
	}
	runner, err := edge.New(cfg, version)
	if err != nil {
		log.Fatal(err)
	}
	if *checkConfig {
		if err := runner.ValidateConfig(); err != nil {
			log.Fatal(err)
		}
		log.Print("configuration and credentials valid")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("campus-link-edge version=%s site=%s", version, cfg.Site)
	if err := runner.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
