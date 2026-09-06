package buildinfo

import "testing"

func TestCurrentReflectsLinkTimeVariables(t *testing.T) {
	oldVersion, oldCommit, oldDate := Version, Commit, BuildDate
	t.Cleanup(func() { Version, Commit, BuildDate = oldVersion, oldCommit, oldDate })
	Version, Commit, BuildDate = "v9.8.7", "abcdef123456", "2026-08-08T12:00:00Z"
	got := Current()
	if got.Version != Version || got.Commit != Commit || got.BuildDate != BuildDate {
		t.Fatalf("Current() = %#v, want linked variables", got)
	}
}
