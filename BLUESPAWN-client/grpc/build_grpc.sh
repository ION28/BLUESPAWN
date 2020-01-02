#!/bin/bash
set -ex;

main() {
	source build_config.sh
	
	rm -rf "$cpp_output_dir"
	mkdir "$cpp_output_dir"
	rm -rf "$csharp_output_dir"
	mkdir "$csharp_output_dir"
	
	# Turn all relative paths to absolute
	cur_dir=$(pwd)
	
	cd "$cpp_output_dir"	
	cpp_output_dir=$(pwd)
	cd "$cur_dir"
	
	cd "$csharp_output_dir"	
	csharp_output_dir=$(pwd)
	cd "$cur_dir"
	
	cd "$proto_dir"	
	proto_dir=$(pwd)
	cd "$cur_dir"
	
	# Go to gRPC plugin location so they can be used
	cd "$grpc_src_location/bins/opt"	
	
	for i in "${proto_files[@]}"
	do
		# Generate C++ files
		protoc -I "$proto_dir/" "--grpc_out=$cpp_output_dir/" "--plugin=protoc-gen-grpc=grpc_cpp_plugin" "$proto_dir/$i"
		protoc -I "$proto_dir/" "--cpp_out=$cpp_output_dir/" "$proto_dir/$i"
		
		# Generate C# files
		protoc -I "$proto_dir/" "--grpc_out=$csharp_output_dir/" "--plugin=protoc-gen-grpc=grpc_csharp_plugin" "$proto_dir/$i"
		protoc -I "$proto_dir/" "--csharp_out=$csharp_output_dir/" "$proto_dir/$i"
	done
}

main "$@"