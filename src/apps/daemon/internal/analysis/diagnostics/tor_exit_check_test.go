package diagnostics

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeTorResolver struct {
	answers []string
	err     error
}

func (f fakeTorResolver) LookupHost(context.Context, string) ([]string, error) {
	return append([]string(nil), f.answers...), f.err
}

func TestTorDNSELQueryName(t *testing.T) {
	got, err := TorDNSELQueryName("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got != "4.3.2.1.dnsel.torproject.org" {
		t.Fatalf("query=%q", got)
	}
	if _, err := TorDNSELQueryName("2001:db8::1"); err == nil {
		t.Fatal("IPv6 unexpectedly accepted by IPv4 DNSEL helper")
	}
}

func TestCheckTorExitTriState(t *testing.T) {
	ctx := context.Background()
	exit, err := CheckTorExit(ctx, "185.220.101.21", fakeTorResolver{answers: []string{"127.0.0.2"}})
	if err != nil || exit.Status != TorExitYes {
		t.Fatalf("exit=%+v err=%v", exit, err)
	}
	notExit, err := CheckTorExit(ctx, "1.2.3.4", fakeTorResolver{err: &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}})
	if err != nil || notExit.Status != TorExitNo {
		t.Fatalf("notExit=%+v err=%v", notExit, err)
	}
	unknown, err := CheckTorExit(ctx, "1.2.3.4", fakeTorResolver{err: errors.New("resolver offline")})
	if err != nil || unknown.Status != TorExitUnknown {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
}
