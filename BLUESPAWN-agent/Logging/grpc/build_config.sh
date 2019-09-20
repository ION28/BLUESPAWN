#!/bin/bash
set -ex;

cpp_output_dir="generated"
csharp_output_dir="../../../BLUESPAWN-server/grpc/generated"
proto_dir="protos"
proto_files=("ReactionData.proto" "ServerServices.proto")
grpc_src_location="/home/calvin/Downloads/grpc"