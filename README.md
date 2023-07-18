# Envoy's ExtAuthZ with a Rust Service

## Proto Sources

+ [envoy/*](https://github.com/envoyproxy/envoy/tree/main/api/envoy)  
+ [google/rpc/*](https://github.com/googleapis/googleapis/blob/master/google/rpc)  
+ [udpa/annotations/*](https://github.com/cncf/udpa/tree/main/udpa/annotations)  
+ [validate/validate.proto](https://github.com/bufbuild/protoc-gen-validate/blob/main/validate/validate.proto)  
+ [xds/*](https://github.com/cncf/xds/tree/main/xds)  

## Compiling protos to Rust

```console
$ cd ./proto

$ PROTO_PATH=...

$ dev protoc -I=./ ./$PROTO_PATH/*.proto \
    --prost_out=./target/$PROTO_PATH \
    --tonic_out=./target/$PROTO_PATH
```

```bash
# Main target

$ PROTO_PATH=envoy/service/auth/v3

# Compile dependencies that need to be imported in the rust pb mod

$ PROTO_PATH=envoy/config/core/v3

$ PROTO_PATH=envoy/type/v3

$ PROTO_PATH=xds/core/v3

$ PROTO_PATH=google/rpc
```