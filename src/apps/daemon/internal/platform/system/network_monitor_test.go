package system

import (
	"context"
	"errors"
	"testing"
	"time"
)

func snap(name, addr, v4 string) NetworkSnapshot {
	s := NetworkSnapshot{Interfaces: []InterfaceState{{Index: 1, Name: name, Addresses: []string{addr}}}, DefaultIPv4Interface: name, DefaultIPv4LocalIP: v4}
	s.Fingerprint = fingerprintNetwork(s)
	return s
}

func TestNetworkMonitorRevisionChangesOnlyOnMeaningfulState(t *testing.T) {
	seq := []NetworkSnapshot{snap("eth0", "10.0.0.2/24", "10.0.0.2"), snap("eth0", "10.0.0.2/24", "10.0.0.2"), snap("wlan0", "192.0.2.4/24", "192.0.2.4")}
	i := 0
	m := newNetworkMonitor(time.Hour, 4, func(context.Context) (NetworkSnapshot, error) {
		s := seq[i]
		if i < len(seq)-1 {
			i++
		}
		return s, nil
	})
	first, err := m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	third, err := m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || second.Revision != 1 || third.Revision != 2 {
		t.Fatalf("revisions=%d,%d,%d", first.Revision, second.Revision, third.Revision)
	}
	st := m.Status(10)
	if len(st.History) != 1 || st.History[0].Revision != 2 {
		t.Fatalf("history=%+v", st.History)
	}
	if len(st.History[0].Kinds) == 0 {
		t.Fatal("missing change kinds")
	}
}

func TestNetworkMonitorHistoryBoundAndCopyIsolation(t *testing.T) {
	i := 0
	m := newNetworkMonitor(time.Hour, 2, func(context.Context) (NetworkSnapshot, error) {
		i++
		return snap(string(rune('a'+i)), "10.0.0.1/24", "10.0.0.1"), nil
	})
	for j := 0; j < 4; j++ {
		if _, err := m.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	st := m.Status(10)
	if len(st.History) != 2 {
		t.Fatalf("history=%d", len(st.History))
	}
	st.Current.Interfaces[0].Addresses[0] = "mutated"
	if m.Snapshot().Interfaces[0].Addresses[0] == "mutated" {
		t.Fatal("snapshot aliases internal state")
	}
}

func TestNetworkMonitorLinkMetadataAdvancesEpoch(t *testing.T) {
	first := snap("eth0", "10.0.0.2/24", "10.0.0.2")
	first.Interfaces[0].MTU = 1500
	first.Interfaces[0].HardwareAddr = "00:11:22:33:44:55"
	first.Interfaces[0].Flags = []string{"up", "running"}
	first.Fingerprint = fingerprintNetwork(first)
	second := cloneNetworkSnapshot(first)
	second.Interfaces[0].MTU = 1280
	second.Fingerprint = fingerprintNetwork(second)
	seq := []NetworkSnapshot{first, second}
	i := 0
	m := newNetworkMonitor(time.Hour, 4, func(context.Context) (NetworkSnapshot, error) {
		s := seq[i]
		if i < len(seq)-1 {
			i++
		}
		return s, nil
	})
	if got, err := m.Refresh(context.Background()); err != nil || got.Revision != 1 {
		t.Fatalf("first=%+v err=%v", got, err)
	}
	got, err := m.Refresh(context.Background())
	if err != nil || got.Revision != 2 {
		t.Fatalf("second=%+v err=%v", got, err)
	}
	st := m.Status(1)
	if len(st.History) != 1 || len(st.History[0].Kinds) != 1 || st.History[0].Kinds[0] != "interfaces" {
		t.Fatalf("history=%+v", st.History)
	}
}

func TestNetworkMonitorStatusZeroOmitsHistory(t *testing.T) {
	i := 0
	m := newNetworkMonitor(time.Hour, 4, func(context.Context) (NetworkSnapshot, error) {
		i++
		return snap(string(rune('a'+i)), "10.0.0.1/24", "10.0.0.1"), nil
	})
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := m.Status(0); len(got.History) != 0 {
		t.Fatalf("history=%+v", got.History)
	}
}

func TestNetworkMonitorFailurePreservesLastGood(t *testing.T) {
	calls := 0
	m := newNetworkMonitor(time.Hour, 2, func(context.Context) (NetworkSnapshot, error) {
		calls++
		if calls == 1 {
			return snap("eth0", "10.0.0.2/24", "10.0.0.2"), nil
		}
		return NetworkSnapshot{}, errors.New("enumeration failed")
	})
	first, _ := m.Refresh(context.Background())
	got, err := m.Refresh(context.Background())
	if err == nil || got.Revision != first.Revision {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if m.Status(0).LastError == "" {
		t.Fatal("last error not retained")
	}
}

func TestNetworkMonitorSubscriberCoalescesLatest(t *testing.T) {
	i := 0
	m := newNetworkMonitor(time.Hour, 4, func(context.Context) (NetworkSnapshot, error) {
		i++
		return snap(string(rune('a'+i)), "10.0.0.1/24", "10.0.0.1"), nil
	})
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ch, stop, err := m.Subscribe(1)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for j := 0; j < 3; j++ {
		if _, err := m.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case ev := <-ch:
		if ev.Revision != 4 {
			t.Fatalf("revision=%d want 4", ev.Revision)
		}
	case <-time.After(time.Second):
		t.Fatal("no change event")
	}
}
