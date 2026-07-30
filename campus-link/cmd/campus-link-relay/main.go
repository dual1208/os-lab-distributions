package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/relay"
)

var version = "dev"

func main() {
	path := flag.String("config", "/etc/campus-link/relay.json", "relay configuration")
	checkConfig := flag.Bool("check-config", false, "validate configuration and credentials without starting")
	flag.Parse()
	var cfg config.Relay
	if err := config.Load(*path, &cfg); err != nil {
		log.Fatal(err)
	}
	if *checkConfig {
		srv, err := relay.NewForPreflight(cfg, version)
		if err != nil {
			log.Fatal(err)
		}
		if err := srv.ValidateConfig(); err != nil {
			log.Fatal(err)
		}
		log.Print("configuration and credentials valid")
		return
	}
	srv, err := relay.New(cfg, version)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("campus-link-relay version=%s", version)
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
