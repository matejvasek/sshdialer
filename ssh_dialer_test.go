package sshdialer_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/matejvasek/sshdialer"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/homedir"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// IPs of test container.
var containerIP4 string
var containerIP6 string

// We need to set up the test container running sshd against which we will run tests.
// This code will populate global containerIP4 and containerIP6 variable
// with the IP address of the test container running ssh.
func TestMain(m *testing.M) {
	var exit int
	defer func() {
		os.Exit(exit)
	}()
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create client: %v\n", err)
		exit = 1

		return
	}

	ctr, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "docker.io/mvasek/docker-ssh-helper-test-img",
	}, nil, nil, nil, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create container: %v\n", err)
		exit = 1

		return
	}

	defer cli.ContainerRemove(ctx, ctr.ID, types.ContainerRemoveOptions{})

	ctrStartOpts := types.ContainerStartOptions{}
	err = cli.ContainerStart(ctx, ctr.ID, ctrStartOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start container: %v\n", err)
		exit = 1

		return
	}

	defer cli.ContainerKill(ctx, ctr.ID, "SIGKILL")

	ctrJSON, err := cli.ContainerInspect(ctx, ctr.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to inspect container: %v\n", err)
		exit = 1

		return
	}

	containerIP4 = ctrJSON.NetworkSettings.IPAddress
	containerIP6 = ctrJSON.NetworkSettings.GlobalIPv6Address

	// wait for ssh container to start serving ssh
	timeoutChan := time.After(time.Second * 10)
	for {
		select {
		case <-timeoutChan:
			fmt.Fprintf(os.Stderr, "test container failed to start serving ssh")
			exit = 1

			return
		case <-time.After(time.Millisecond * 100):
		}

		conn, err := net.Dial("tcp", net.JoinHostPort(containerIP4, "22"))
		if err != nil {
			continue
		}
		conn.Close()

		break
	}

	// unsetting HOME just be sure test won't mess with actual user ~/.ssh/
	homeEnvVar := "HOME"
	if runtime.GOOS == "windows" {
		homeEnvVar = "USERPROFILE"
	}
	os.Unsetenv(homeEnvVar)

	// unsetting path to ssh-agent just to be sure test won't mess with actual user ssh-agent state
	os.Unsetenv("SSH_AUTH_SOCK")

	exit = m.Run()
}

// function that prepares testing environment and returns clean up function
// this should be used in conjunction with defer: `defer fn()()`
// e.g. sets environment variables or starts mock up services
// it returns clean up procedure that restores old values of environment variables
// or shuts down mock up services
type setUpEnvFn func(t *testing.T) func()

// combines multiple setUp routines into one setUp routine
func all(fns ...setUpEnvFn) setUpEnvFn {
	return func(t *testing.T) func() {
		t.Helper()
		var cleanUps []func()
		for _, fn := range fns {
			cleanUps = append(cleanUps, fn(t))
		}

		return func() {
			for i := len(cleanUps) - 1; i >= 0; i-- {
				cleanUps[i]()
			}
		}
	}
}

func TestCreateDialer(t *testing.T) {

	type args struct {
		connStr    string
		identity   string
		passPhrase string
	}
	type testParams struct {
		name     string
		args     args
		setUpEnv setUpEnvFn
		ipv6test bool
		errMsg   string
	}
	tests := []testParams{
		{
			name:     "read password from input",
			args:     args{connStr: fmt.Sprintf("ssh://testuser@%s/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKnowHosts),
			errMsg:   sshdialer.ErrNotImplementedMsg,
		},
		{
			name:     "password in url",
			args:     args{connStr: fmt.Sprintf("ssh://testuser:idkfa@%s/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKnowHosts),
		},
		{
			name:     "password in url non-standard ssh port",
			args:     args{connStr: fmt.Sprintf("ssh://testuser:idkfa@%s:2222/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKnowHosts),
		},
		{
			name:     "server key is not in known_hosts",
			args:     args{connStr: fmt.Sprintf("ssh://testuser:idkfa@%s/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withoutSSHAgent, withCleanHome),
			errMsg:   sshdialer.ErrUnknownServerKeyMsg,
		},
		{
			name:     "server key does not match the respective key in known_host",
			args:     args{connStr: fmt.Sprintf("ssh://testuser:idkfa@%s/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withBadKnownHosts),
			errMsg:   sshdialer.ErrBadServerKeyMsg,
		},
		{
			name: "key from identity parameter",
			args: args{
				connStr:  fmt.Sprintf("ssh://testuser@%s/home/testuser/test.sock", containerIP4),
				identity: "testdata/id_ed25519",
			},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKnowHosts),
		},
		{
			name:     "key at standard location with need to read passphrase",
			args:     args{connStr: fmt.Sprintf("ssh://testuser@%s/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKey(t, "id_rsa"), withKnowHosts),
			errMsg:   sshdialer.ErrNotImplementedMsg,
		},
		{
			name: "key at standard location with explicitly set passphrase",
			args: args{
				connStr:    fmt.Sprintf("ssh://testuser@%s/home/testuser/test.sock", containerIP4),
				passPhrase: "idfa",
			},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKey(t, "id_rsa"), withKnowHosts),
		},
		{
			name:     "key at standard location with no passphrase",
			args:     args{connStr: fmt.Sprintf("ssh://testuser@%s/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKey(t, "id_ed25519"), withKnowHosts),
		},
		{
			name:     "key from ssh-agent",
			args:     args{connStr: fmt.Sprintf("ssh://testuser@%s/home/testuser/test.sock", containerIP4)},
			setUpEnv: all(withSSHAgent, withCleanHome, withKnowHosts),
		},
		{
			name:     "password in url with IPv6",
			args:     args{connStr: fmt.Sprintf("ssh://testuser:idkfa@[%s]/home/testuser/test.sock", containerIP6)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKnowHosts),
			ipv6test: true,
		},
		{
			name:     "password in url with IPv6 non-standard port",
			args:     args{connStr: fmt.Sprintf("ssh://testuser:idkfa@[%s]:2222/home/testuser/test.sock", containerIP6)},
			setUpEnv: all(withoutSSHAgent, withCleanHome, withKnowHosts),
			ipv6test: true,
		},
	}

	for _, ttx := range tests {
		tt := ttx
		t.Run(tt.name, func(t *testing.T) {
			// this test cannot be parallelized as they use process wide environment variable $HOME
			if strings.Contains(tt.errMsg, sshdialer.ErrNotImplementedMsg) {
				t.Skip("functionality is yet to be implemented")
			}

			if tt.ipv6test && containerIP6 == "" {
				t.Skip("skipping ipv6 test since test environment doesn't support ipv6 connection")
			}

			defer tt.setUpEnv(t)()

			u, err := url.Parse(tt.args.connStr)
			if err != nil {
				t.Fatal(err)
			}

			DialContext, err := sshdialer.CreateDialContext(u, tt.args.identity, tt.args.passPhrase)

			assert.NoError(t, err)
			if err != nil {
				return
			}

			transport := http.Transport{DialContext: DialContext}
			httpClient := http.Client{Transport: &transport}

			resp, err := httpClient.Get("http://dummy/")

			if tt.errMsg == "" {
				assert.NoError(t, err)
			} else {
				// I wish I could use errors.Is(),
				// however foreign code is not wrapping errors thoroughly
				assert.Contains(t, err.Error(), tt.errMsg)
			}
			if err != nil {
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, "Hello there!", string(b))
		})
	}
}

func cp(src, dest string) error {
	srcFs, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("the cp() function failed to stat source file: %w", err)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("the cp() function failed to read source file: %w", err)
	}

	_, err = os.Stat(dest)
	if err == nil {
		return fmt.Errorf("destination file already exists: %w", os.ErrExist)
	}

	return os.WriteFile(dest, data, srcFs.Mode())
}

// puts key from ./testdata/{keyName} to $HOME/.ssh/{keyName}
// those keys are also supposed to be in authorized_keys of the test container
func withKey(t *testing.T, keyName string) func(t *testing.T) func() {
	t.Helper()

	return func(t *testing.T) func() {
		t.Helper()
		var err error

		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}

		err = os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
		if err != nil {
			t.Fatal(err)
		}

		keySrc := filepath.Join("testdata", keyName)
		keyDest := filepath.Join(home, ".ssh", keyName)
		err = cp(keySrc, keyDest)
		if err != nil {
			t.Fatal(err)
		}

		return func() {
			os.Remove(keyDest)
		}
	}
}

// sets clean temporary $HOME for test
// this prevents interaction with actual user home which may contain .ssh/
func withCleanHome(t *testing.T) func() {
	t.Helper()
	homeName := "HOME"
	if runtime.GOOS == "windows" {
		homeName = "USERPROFILE"
	}
	tmpDir := t.TempDir()
	oldHome, hadHome := os.LookupEnv(homeName)
	os.Setenv(homeName, tmpDir)

	return func() {
		if hadHome {
			os.Setenv(homeName, oldHome)
		} else {
			os.Unsetenv(homeName)
		}
	}
}

// generates `known_hosts` with test container keys and puts it into $HOME/.ssh/known_hosts
func withKnowHosts(t *testing.T) func() {
	t.Helper()
	knownHosts := filepath.Join(homedir.Get(), ".ssh", "known_hosts")

	err := os.MkdirAll(filepath.Join(homedir.Get(), ".ssh"), 0700)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(knownHosts)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("known_hosts already exists")
	}

	f, err := os.OpenFile(knownHosts, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// generate known_hosts
	serverKeysDir := filepath.Join("testdata", "etc", "ssh")
	for _, k := range []string{"dsa", "ecdsa", "ed25519", "rsa"} {
		keyPath := filepath.Join(serverKeysDir, fmt.Sprintf("ssh_host_%s_key.pub", k))
		key, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(t)
		}

		fmt.Fprintf(f, "%s %s", containerIP4, string(key))
		fmt.Fprintf(f, "[%s]:2222 %s", containerIP4, string(key))

		if containerIP6 != "" {
			fmt.Fprintf(f, "%s %s", containerIP6, string(key))
			fmt.Fprintf(f, "[%s]:2222 %s", containerIP6, string(key))
		}
	}

	return func() {
		os.Remove(knownHosts)
	}
}

// creates $HOME/.ssh/known_hosts such that is does not match with keys in the test container
func withBadKnownHosts(t *testing.T) func() {
	t.Helper()

	knownHosts := filepath.Join(homedir.Get(), ".ssh", "known_hosts")

	err := os.MkdirAll(filepath.Join(homedir.Get(), ".ssh"), 0700)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(knownHosts)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("known_hosts already exists")
	}

	f, err := os.OpenFile(knownHosts, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	knownHostTemplate := `{{range $host := .}}{{$host}} ssh-dss AAAAB3NzaC1kc3MAAACBAKH4ufS3ABVb780oTgEL1eu+pI1p6YOq/1KJn5s3zm+L3cXXq76r5OM/roGEYrXWUDGRtfVpzYTAKoMWuqcVc0AZ2zOdYkoy1fSjJ3MqDGF53QEO3TXIUt3gUzmLOewwmZWle0RgMa9GHccv7XVVIZB36RR68ZEUswLaTnlVhXQ1AAAAFQCl4t/LnY7kuUI+tL2qT2XmxmiyqwAAAIB72XaO+LfyIiqBOaTkQf+5rvH1i6y6LDO1QD9pzGWUYw3y03AEveHJMjW0EjnYBKJjK39wcZNTieRyU54lhH/HWeWABn9NcQ3duEf1WSO/s7SPsFO2R6quqVSsStkqf2Yfdy4fl24mH41olwtNA6ft5nkVfkqrIa51si4jU8fBVAAAAIB8SSvyYBcyMGLUlQjzQqhhhAHer9x/1YbknVz+y5PHJLLjHjMC4ZRfLgNEojvMKQW46Te9Pwnudcwv19ho4F+kkCOfss7xjyH70gQm6Sj76DxClmnnPoSRq3qEAOMy5Oh+7vyzxm68KHqd/aOmUaiT1LgqgViS9+kNdCoVMGAMOg== mvasek@bellatrix
{{$host}} ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLTxVVaQ93ReqHNlbjg5/nBRpuRuG6JIgNeJXWT1V4Dl+dMMrnad3uJBfyrNpvn8rv2qnn6gMTZVtTbLdo96pG0= mvasek@bellatrix
{{$host}} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOKymJNQszrxetVffPZRfZGKWK786r0mNcg/Wah4+2wn mvasek@bellatrix
{{$host}} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/1/OCwec2Gyv5goNYYvos4iOA+a0NolOGsZA/93jmSArPY1zZS1UWeJ6dDTmxGoL/e7jm9lM6NJY7a/zM0C/GqCNRGR/aCUHBJTIgGtH+79FDKO/LWY6ClGY7Lw8qNgZpugbBw3N3HqTtyb2lELhFLT0FEb+le4WUbryooLK2zsz6DnqV4JvTYyyHcanS0h68iSXC7XbkZchvL99l5LT0gD1oDteBPKKFdNOwIjpMkk/IrbFM24xoNkaTDXN87EpQPQzYDfsoGymprc5OZZ8kzrtErQR+yfuunHfzzqDHWi7ga5pbgkuxNt10djWgCfBRsy07FTEgV0JirS0TCfwTBbqRzdjf3dgi8AP+WtkW3mcv4a1XYeqoBo2o9TbfyiA9kERs79UBN0mCe3KNX3Ns0PvutsRLaHmdJ49eaKWkJ6GgL37aqSlIwTixz2xY3eoDSkqHoZpx6Q1MdpSIl5gGVzlaobM/PNM1jqVdyUj+xpjHyiXwHQMKc3eJna7s8Jc= mvasek@bellatrix
{{end}}`

	tmpl := template.New(knownHostTemplate)
	tmpl, err = tmpl.Parse(knownHostTemplate)
	if err != nil {
		t.Fatal(err)
	}

	hosts := make([]string, 0, 4)
	hosts = append(hosts, containerIP4, fmt.Sprintf("[%s]:2222", containerIP4))
	if containerIP6 != "" {
		hosts = append(hosts, containerIP6, fmt.Sprintf("[%s]:2222", containerIP6))
	}

	err = tmpl.Execute(f, hosts)
	if err != nil {
		t.Fatal(err)
	}

	return func() {
		os.Remove(knownHosts)
	}
}

// unsets environment variable so ssh-agent is not used by test
func withoutSSHAgent(t *testing.T) func() {
	t.Helper()
	oldAuthSock, hadAuthSock := os.LookupEnv("SSH_AUTH_SOCK")
	os.Unsetenv("SSH_AUTH_SOCK")

	return func() {
		if hadAuthSock {
			os.Setenv("SSH_AUTH_SOCK", oldAuthSock)
		} else {
			os.Unsetenv("SSH_AUTH_SOCK")
		}
	}
}

// starts serving ssh-agent on temporary unix socket
// returns clean up routine that stops the server
func withSSHAgent(t *testing.T) func() {
	t.Helper()

	key, err := ioutil.ReadFile(filepath.Join("testdata", "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	tmpDirForSocket := t.TempDir()
	agentSocketPath := filepath.Join(tmpDirForSocket, "agent.sock")
	unixListener, err := net.Listen("unix", agentSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("SSH_AUTH_SOCK", agentSocketPath)

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	var wg sync.WaitGroup

	go func() {
		for {
			conn, err := unixListener.Accept()
			if err != nil {
				errChan <- err

				return
			}

			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				go func() {
					<-ctx.Done()
					conn.Close()
				}()
				err := agent.ServeAgent(signerAgent{signer}, conn)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						fmt.Fprintf(os.Stderr, "agent.ServeAgent() failed: %v\n", err)
					}
				}
			}(conn)
		}
	}()

	return func() {
		os.Unsetenv("SSH_AUTH_SOCK")

		err := unixListener.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = <-errChan
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		cancel()
		wg.Wait()
	}
}

type signerAgent struct {
	impl ssh.Signer
}

func (a signerAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{
		Format: a.impl.PublicKey().Type(),
		Blob:   a.impl.PublicKey().Marshal(),
	}}, nil
}

func (a signerAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.impl.Sign(nil, data)
}

func (a signerAgent) Add(key agent.AddedKey) error {
	panic("implement me")
}

func (a signerAgent) Remove(key ssh.PublicKey) error {
	panic("implement me")
}

func (a signerAgent) RemoveAll() error {
	panic("implement me")
}

func (a signerAgent) Lock(passphrase []byte) error {
	panic("implement me")
}

func (a signerAgent) Unlock(passphrase []byte) error {
	panic("implement me")
}

func (a signerAgent) Signers() ([]ssh.Signer, error) {
	panic("implement me")
}
