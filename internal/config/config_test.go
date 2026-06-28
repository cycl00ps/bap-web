package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(path, []byte(`
server:
  bind_address: "127.0.0.1"
  port: 9090
database:
  driver: "sqlite"
  dsn: "`+filepath.Join(dir, "db.sqlite")+`"
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Port != 9090 {
		t.Fatalf("port = %d", cfg.Server.Port)
	}
	if cfg.Network.DefaultNetworkMode != "routed_ptp" {
		t.Fatalf("default network mode = %q", cfg.Network.DefaultNetworkMode)
	}
}
