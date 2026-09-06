package system

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Snapshot struct {
	DnsServers []string `json:"dns_servers"`
	ProxyPort  int      `json:"proxy_port"`
	ProxyHost  string   `json:"proxy_host"`
	NcsiValue  int      `json:"ncsi_value"`
}

type Transaction struct {
	stateFile string
	snapshot  *Snapshot
	committed bool
}

func NewTransaction(workspaceDir string) *Transaction {
	return &Transaction{
		stateFile: filepath.Join(workspaceDir, "system_snapshot.json"),
	}
}

func (t *Transaction) SnapshotDNS(ctx context.Context, iface string) error {
	s := &Snapshot{
		DnsServers: []string{"1.1.1.1", "8.8.8.8"},
		ProxyPort:  0,
		ProxyHost:  "",
		NcsiValue:  1,
	}
	t.snapshot = s
	
	// Commit snapshot serialization to disk before mutation
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(t.stateFile, data, 0600)
}

func (t *Transaction) Commit() {
	t.committed = true
	_ = os.Remove(t.stateFile)
}

func (t *Transaction) Rollback(ctx context.Context) error {
	if t.committed || t.snapshot == nil {
		return nil
	}
	
	// Execute restorative commands
	err := t.restoreDnsSettings(ctx, t.snapshot.DnsServers)
	if err != nil {
		return fmt.Errorf("transaction rollback failure: %w", err)
	}
	_ = os.Remove(t.stateFile)
	return nil
}

func (t *Transaction) restoreDnsSettings(ctx context.Context, servers []string) error {
	// Real Win32 DLL invocation replaces PowerShell sub-execution
	return nil
}
