package main

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/matejvasek/sshdialer"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
)


// simple app that list images from docker daemon (or podman) in remote machine (or VM) via SSH
func main() {

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-sigs
		cancel()
		<-sigs
		os.Exit(1)
	}()

	// put your remote here
	host := "ssh://core@localhost:44625/run/user/1000/podman/podman.sock"

	// optionally put path to your identity (private key) here
	// if empty info from ~/.ssh/ or ssh-agent will be used
	identity := ""

	// optionally put passphrase to your identity (private key) here
	passPhrase := ""

	_url, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}

	if _url.Scheme != "ssh" {
		log.Fatal("only ssh is supported by sshdialer")
	}

	dialer, err := sshdialer.CreateDialContext(_url, identity, passPhrase)
	if err != nil {
		log.Fatal(err)
	}

	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
		client.WithDialContext(dialer),
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		log.Fatal(err)
	}

	images, err := cli.ImageList(ctx, types.ImageListOptions{All: true})
	if err != nil {
		log.Fatal(err)
	}

	for _, image := range images {
		fmt.Printf("image id: %v\n", image.ID)
		fmt.Printf("image tags: %v\n", image.RepoTags)
	}
}
