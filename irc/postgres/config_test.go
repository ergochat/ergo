// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package postgres

import (
	"testing"
	"time"
)

func testBuildURI(t *testing.T, config Config, expected string) {
	t.Helper()
	uri, err := config.buildURI()
	if err != nil {
		t.Fatal(err)
	}
	if uri != expected {
		t.Errorf("got %q, want %q", uri, expected)
	}
}

func TestBuildURITCP(t *testing.T) {
	testBuildURI(t, Config{
		Host:            "db.example.com",
		Port:            5432,
		User:            "ergo",
		Password:        "secret",
		HistoryDatabase: "ergo_history",
	}, "postgresql://ergo:secret@db.example.com:5432/ergo_history?sslmode=disable")
}

func TestBuildURIDefaultPort(t *testing.T) {
	testBuildURI(t, Config{
		Host:            "localhost",
		HistoryDatabase: "ergo_history",
	}, "postgresql://localhost:5432/ergo_history?sslmode=disable")
}

func TestBuildURIDefaultHost(t *testing.T) {
	testBuildURI(t, Config{
		HistoryDatabase: "ergo_history",
	}, "postgresql://localhost:5432/ergo_history?sslmode=disable")
}

func TestBuildURISSLMode(t *testing.T) {
	testBuildURI(t, Config{
		Host:            "db.example.com",
		Port:            5432,
		HistoryDatabase: "ergo_history",
		SSLMode:         "verify-full",
		SSLCert:         "/etc/ssl/client.crt",
		SSLKey:          "/etc/ssl/client.key",
		SSLRootCert:     "/etc/ssl/ca.crt",
	}, "postgresql://db.example.com:5432/ergo_history?sslcert=%2Fetc%2Fssl%2Fclient.crt&sslkey=%2Fetc%2Fssl%2Fclient.key&sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fca.crt")
}

func TestBuildURIUnixSocket(t *testing.T) {
	testBuildURI(t, Config{
		SocketPath:      "/var/run/postgresql",
		User:            "ergo",
		Password:        "secret",
		HistoryDatabase: "ergo_history",
	}, "postgresql://ergo:secret@/ergo_history?host=%2Fvar%2Frun%2Fpostgresql")
}

func TestBuildURISpecialCharsInPassword(t *testing.T) {
	testBuildURI(t, Config{
		Host:            "db.example.com",
		Port:            5432,
		User:            "ergo",
		Password:        "p@ss:w/ord?#&=",
		HistoryDatabase: "ergo_history",
	}, "postgresql://ergo:p%40ss%3Aw%2Ford%3F%23&=@db.example.com:5432/ergo_history?sslmode=disable")
}

func TestBuildURIOptionalParams(t *testing.T) {
	testBuildURI(t, Config{
		Host:            "db.example.com",
		Port:            5433,
		HistoryDatabase: "ergo_history",
		ApplicationName: "ergo",
		ConnectTimeout:  30 * time.Second,
	}, "postgresql://db.example.com:5433/ergo_history?application_name=ergo&connect_timeout=30&sslmode=disable")
}
