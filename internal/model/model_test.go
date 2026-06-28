package model

import "testing"

func TestCleanKernelTestOutputRemovesKnownHostWarning(t *testing.T) {
	dirty := "Warning: Permanently added '172.31.0.2' (ED25519) to the list of known hosts. 5.10.245+ gateway-ok"

	clean := CleanKernelTestOutput(dirty)
	release, gatewayOK, summary := ParseKernelTestResult(dirty)

	if clean != "5.10.245+ gateway-ok" {
		t.Fatalf("clean = %q", clean)
	}
	if release != "5.10.245+" {
		t.Fatalf("release = %q", release)
	}
	if gatewayOK == nil || !*gatewayOK {
		t.Fatalf("gatewayOK = %#v", gatewayOK)
	}
	if summary != "5.10.245+, gateway OK" {
		t.Fatalf("summary = %q", summary)
	}
}
