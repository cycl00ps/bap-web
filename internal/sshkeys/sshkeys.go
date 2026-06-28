package sshkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"bap-web/internal/model"
	"bap-web/internal/random"

	"golang.org/x/crypto/ssh"
)

type GeneratedKey struct {
	Key        model.SSHKey
	PrivateKey string
}

func Generate(name, createdBy string) (*GeneratedKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("key name is required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "bap-web:"+name)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &GeneratedKey{
		Key: model.SSHKey{
			ID:          random.Hex(8),
			Name:        name,
			PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
			Fingerprint: ssh.FingerprintSHA256(pub),
			KeyType:     pub.Type(),
			CreatedBy:   createdBy,
			CreatedAt:   now,
		},
		PrivateKey: string(pem.EncodeToMemory(block)),
	}, nil
}

func Import(name, publicKey, createdBy string) (*model.SSHKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("key name is required")
	}
	normalized, fingerprint, keyType, err := NormalizePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return &model.SSHKey{
		ID:          random.Hex(8),
		Name:        name,
		PublicKey:   normalized,
		Fingerprint: fingerprint,
		KeyType:     keyType,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func NormalizePublicKey(publicKey string) (string, string, string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	if err != nil {
		return "", "", "", fmt.Errorf("invalid SSH public key: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), ssh.FingerprintSHA256(pub), pub.Type(), nil
}
