package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/ultravioletrs/cocos/pkg/clients"
	cvmsgrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/cvm"
)

func main() {
	slog.Info("Starting gRPC connection test")

	cfg := clients.StandardClientConfig{}
	cfg.URL = "192.168.100.15:7001"

	slog.Info("Creating gRPC client", "url", cfg.URL)
	grpcClient, cvmsClient, err := cvmsgrpc.NewCVMClient(cfg)
	if err != nil {
		log.Fatal("Failed to create client:", err)
	}
	defer grpcClient.Close()
	slog.Info("gRPC client created successfully")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	slog.Info("Calling Process() to establish stream")
	pc, err := cvmsClient.Process(ctx)
	if err != nil {
		log.Fatal("Failed to call Process():", err)
	}
	slog.Info("Process() returned successfully!")

	// Try to receive a message
	slog.Info("Waiting for first message from server")
	msg, err := pc.Recv()
	if err != nil {
		log.Fatal("Failed to receive:", err)
	}

	fmt.Printf("Received message: %+v\n", msg)
	slog.Info("Test completed successfully")
}
