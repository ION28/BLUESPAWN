package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	pb "BLUESPAWN/BLUESPAWN-common/bluespawnpb"
)

const (
	port = ":50052"
)

type server struct {
	pb.UnimplementedLogReceiverServer
}

func (s *server) SendLog(ctx context.Context, in *pb.LogMessageRequest) (*pb.LogMessageResponse, error) {
	log.Printf("Received: %v", in.GetMessage())
	return &pb.LogMessageResponse{Received: true}, nil
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterLogReceiverServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
