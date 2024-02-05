package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/ultravioletrs/cocos/manager"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	"google.golang.org/grpc"
)

type svc struct{}

func (s *svc) Run(ipAdress string) manager.ComputationRunReq {
	log.Println("received who am on ip address", ipAdress)
	return manager.ComputationRunReq{
		Id:              "1",
		Name:            "sample computation",
		Description:     "sample descrption",
		Datasets:        []*manager.Dataset{{Id: "1", Provider: "provider1"}},
		Algorithms:      []*manager.Algorithm{{Id: "1", Provider: "provider1"}},
		ResultConsumers: []string{"consumer1"},
		AgentConfig: &manager.AgentConfig{
			Port:     "7002",
			LogLevel: "debug",
		},
	}
}

func main() {

	incomingChan := make(chan *manager.ClientStreamMessage)

	svc := managergrpc.NewServer(context.Background(), incomingChan, &svc{})

	go func() {
		for incoming := range incomingChan {
			switch incoming.Message.(type) {
			case *manager.ClientStreamMessage_WhoamiRequest:
				fmt.Println("recived whoamI")
			case *manager.ClientStreamMessage_RunRes:
				fmt.Println("recived runRes")
			case *manager.ClientStreamMessage_AgentEvent:
				fmt.Println("recived agent event")
			case *manager.ClientStreamMessage_AgentLog:
				fmt.Println("recived agent log")
			}
			fmt.Println(incoming.Message)
		}
	}()

	grpcServer := grpc.NewServer()
	manager.RegisterManagerServiceServer(grpcServer, svc)

	lis, err := net.Listen("tcp", ":8282")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Server listening on port 8282")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
