// NOTE: code here is heavily based on podman code

package sshdialer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	urlPkg "net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/pkg/homedir"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// CreateDialContext creates DialContext function
// Useful with docker API client as well as with standard Go http client.
func CreateDialContext(url *urlPkg.URL, identity, passPhrase string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return DialOverSSH(url, identity, passPhrase)
	}, nil
}

// Default key names.
var knownKeyNames = []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"}

// DialOverSSH dials unix socket in the remote machine via ssh tunneling.
// The identity parameter is an optional path to a private key.
// The passPhrase parameter is an optional passPhrase to the identity file
func DialOverSSH(url *urlPkg.URL, identity, passPhrase string) (net.Conn, error) {
	var (
		authMethods []ssh.AuthMethod
		signers     []ssh.Signer
	)

	if pw, found := url.User.Password(); found {
		authMethods = append(authMethods, ssh.Password(pw))
	}

	// add signer from explicit identity parameter
	if identity != "" {
		s, err := publicKey(identity, []byte(passPhrase))
		if err != nil {
			return nil, fmt.Errorf("failed to parse identity file: %w", err)
		}
		signers = append(signers, s)
	}

	// add signers from ssh-agent
	if sock, found := os.LookupEnv("SSH_AUTH_SOCK"); found {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to ssh-agent's socket: %w", err)
		}
		agentSigners, err := agent.NewClient(c).Signers()
		if err != nil {
			return nil, fmt.Errorf("failed to get signers from ssh-agent: %w", err)
		}
		signers = append(signers, agentSigners...)
	}

	// if there is no explicit identity file nor keys from ssh-agent then
	// add keys with standard name from ~/.ssh/
	if len(signers) == 0 {
		var defaultKeyPaths []string
		if home, err := os.UserHomeDir(); err == nil {
			for _, keyName := range knownKeyNames {
				p := filepath.Join(home, ".ssh", keyName)

				fi, err := os.Stat(p)
				if err != nil {
					continue
				}
				if fi.Mode().IsRegular() {
					defaultKeyPaths = append(defaultKeyPaths, p)
				}
			}
		}

		if len(defaultKeyPaths) == 1 {
			s, err := publicKey(defaultKeyPaths[0], []byte(passPhrase))
			if err != nil {
				return nil, err
			}
			signers = append(signers, s)
		}
	}

	if len(signers) > 0 {
		var dedup = make(map[string]ssh.Signer)
		// Dedup signers based on fingerprint, ssh-agent keys override explicit identity
		for _, s := range signers {
			fp := ssh.FingerprintSHA256(s.PublicKey())
			//if _, found := dedup[fp]; found {
			//	key updated
			//}
			dedup[fp] = s
		}

		var uniq []ssh.Signer
		for _, s := range dedup {
			uniq = append(uniq, s)
		}
		authMethods = append(authMethods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return uniq, nil
		}))
	}

	if len(authMethods) == 0 {
		callback := func() (string, error) {
			var pass []byte
			// TODO read password form input here
			err := fmt.Errorf("cannot read password: %w", errNotImplemented)

			return string(pass), err
		}
		authMethods = append(authMethods, ssh.PasswordCallback(callback))
	}

	const sshTimeout = 5
	config := ssh.ClientConfig{
		User:            url.User.Username(),
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoED25519,
			ssh.SigAlgoRSASHA2512,
			ssh.SigAlgoRSASHA2256,
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoDSA,
		},
		Timeout: sshTimeout * time.Second,
	}

	port := url.Port()
	if port == "" {
		port = "22"
	}

	sshClient, err := ssh.Dial("tcp", net.JoinHostPort(url.Hostname(), port), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial ssh: %w", err)
	}
	conn, err := sshClient.Dial("unix", url.Path)
	if err != nil {
		err = fmt.Errorf("failed to dial unix socket in the remote: %w", err)
	}

	return conn, err
}

func publicKey(path string, passphrase []byte) (ssh.Signer, error) {
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		var missingPhraseError *ssh.PassphraseMissingError
		if ok := errors.As(err, &missingPhraseError); !ok {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		if len(passphrase) == 0 {
			// TODO read passphrase form input here
			return nil, fmt.Errorf("cannot read passphrase: %w", errNotImplemented)
		}

		return ssh.ParsePrivateKeyWithPassphrase(key, passphrase)
	}

	return signer, nil
}

func hostKeyCallback(hostPort string, remote net.Addr, key ssh.PublicKey) error {
	// TODO this function might ask user if they wants to add unknown key to known_hosts

	host, port := hostPort, "22"
	if _h, _p, err := net.SplitHostPort(host); err == nil {
		host, port = _h, _p
	}

	knownHosts := filepath.Join(homedir.Get(), ".ssh", "known_hosts")

	_, err := os.Stat(knownHosts)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return errUnknownServerKey
	}

	f, err := os.Open(knownHosts)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}
	defer f.Close()

	hashhost := knownhosts.HashHostname(host)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		_, hostPorts, _key, _, _, err := ssh.ParseKnownHosts(scanner.Bytes())
		if err != nil {
			// return fmt.Errorf("failed to parse known_hosts: %s", scanner.Text())
			// is not being able to parse a line is not critical issue ?
			continue
		}

		for _, hp := range hostPorts {
			h, p := hp, "22"
			if _h, _p, err := net.SplitHostPort(hp); err == nil {
				h, p = _h, _p
			}

			if (h == host || h == hashhost) && port == p {
				if key.Type() != _key.Type() {
					continue
				}
				if bytes.Equal(_key.Marshal(), key.Marshal()) {
					return nil
				}

				return errBadServerKey
			}
		}
	}

	return errUnknownServerKey
}

var ErrBadServerKeyMsg = "server key for given host differs from key in known_host"
var ErrUnknownServerKeyMsg = "server key not found in known_hosts"
var ErrNotImplementedMsg = "not implemented"

// I would expose those but since ssh pkg doesn't do correct error wrapping it would be entirely futile
var errBadServerKey = errors.New(ErrBadServerKeyMsg)
var errUnknownServerKey = errors.New(ErrUnknownServerKeyMsg)
var errNotImplemented = errors.New(ErrNotImplementedMsg)
