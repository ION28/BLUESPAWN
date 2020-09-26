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
	pb.UnimplementedBluespawnRPCServer
}

func (s *server) SendLogMessage(ctx context.Context, in *pb.LogMessage) (*pb.ResponseMessage, error) {
	log.Printf("Received Log Message: %v", in.GetMessage())
	return &pb.ResponseMessage{Received: true, Success: true}, nil
}

func (s *server) RecordDetection(ctx context.Context, in *pb.Detection) (*pb.ResponseMessage, error) {
	log.Printf("Received Detection: ID %d", in.GetId())
	return &pb.ResponseMessage{Received: true, Success: true}, nil
}

func (s *server) AddAssociation(ctx context.Context, in *pb.DetectionAssociation) (*pb.ResponseMessage, error) {
	log.Printf("Received Association for Detection ID %d and ID %d with strength %f", in.GetDetection_Id(), in.GetAssociated_Id(), in.GetStrength())
	return &pb.ResponseMessage{Received: true, Success: true}, nil
}

func (s *server) UpdateCertainty(ctx context.Context, in *pb.DetectionCertaintyUpdate) (*pb.ResponseMessage, error) {
	log.Printf("Received Detection Certainty update for ID %d to %f", in.GetId(), in.GetCertainty())
	return &pb.ResponseMessage{Received: true, Success: true}, nil
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterBluespawnRPCServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
