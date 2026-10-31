package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/Yashbhu/Hades/internal/gateway"
)

func main() {
	config := gateway.ConfigFromEnvironment()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("cypher gateway listening on %s (provider=%s model=%s)\n", config.ListenAddr, config.Provider, config.Model)
	if err := gateway.NewServer(config).ListenAndServe(ctx); err != nil {
		fmt.Println(err)
	}
}
