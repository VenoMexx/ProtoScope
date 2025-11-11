package parser

import (
	"encoding/base64"
	"testing"
)

func TestParseVMessNumericPort(t *testing.T) {
	config := `{"v":"2","ps":"test","add":"example.com","port":2086,"id":"uuid","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"example.com"}`
	url := "vmess://" + base64.StdEncoding.EncodeToString([]byte(config))

	protocol, err := ParseVMess(url)
	if err != nil {
		t.Fatalf("ParseVMess returned error: %v", err)
	}

	if protocol.Port != 2086 {
		t.Fatalf("expected port 2086, got %d", protocol.Port)
	}
}

func TestParseVMessStringPort(t *testing.T) {
	config := `{"v":"2","ps":"test","add":"example.com","port":"2087","id":"uuid","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"example.com"}`
	url := "vmess://" + base64.StdEncoding.EncodeToString([]byte(config))

	protocol, err := ParseVMess(url)
	if err != nil {
		t.Fatalf("ParseVMess returned error: %v", err)
	}

	if protocol.Port != 2087 {
		t.Fatalf("expected port 2087, got %d", protocol.Port)
	}
}
