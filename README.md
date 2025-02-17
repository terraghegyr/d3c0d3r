# d3c0d3r

**Most light weight, simple bulk cipher decoder/encoder website using WASM (also CLI)**

I was so fed up with searching for all-in-one online encoder/decoder which does not send input to a server, is light-weight and easy to use, I decided to create one.

This is as simple as it can get, simple html file loading compilied wasm file to execute encode/decode functions locally on the client side.

# Setup

## /web

Compile WASM file
```bash
GOARCH=wasm GOOS=js go build -o ./web/src/main.wasm ./web/main.go
```

Start dev web server
```
cd web/src

python3 -m http.server
```

## /cli

Compile CLI executable
```
go build -o ./cli/d3c0d3r ./cli/main.go
```