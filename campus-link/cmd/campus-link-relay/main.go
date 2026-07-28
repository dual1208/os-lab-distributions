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
	flag.Parse()
	var cfg config.Relay
	if err := config.Load(*path, &cfg); err != nil {
		log.Fatal(err)
	}
	srv, err := relay.New(cfg)
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
