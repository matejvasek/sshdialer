package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// simple HTTP server to verify that tunneling works
func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	unixListener, err := net.Listen("unix", os.Args[1])
	if err != nil {
		panic(err)
	}
	var handler http.HandlerFunc = func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Hello there!"))
	}
	server := http.Server{Handler: handler}
	go func() {
		<-sigs
		shutdownCtx, _ := context.WithTimeout(context.Background(), time.Second*5)
		server.Shutdown(shutdownCtx)
	}()
	server.Serve(unixListener)
}
