package mobilehost

import "testing"

type testProtector struct{ got int }

func (p *testProtector) Protect(fd int) bool { p.got = fd; return true }

type testFinder struct{ uid int }

func (f testFinder) FindProcessByConnection(string, string, int, string, int) int { return f.uid }

func TestHostCallbacksHaveExplicitUnavailableDefaults(t *testing.T) {
	RegisterSocketProtector(nil)
	RegisterProcessFinder(nil)
	if ProtectSocket(7) {
		t.Fatal("unregistered socket protector reported success")
	}
	if got := FindProcessConnection("tcp", "127.0.0.1", 1, "127.0.0.1", 2); got != -1 {
		t.Fatalf("unregistered process finder = %d, want -1", got)
	}
}

func TestHostCallbacksUseRegisteredAdapters(t *testing.T) {
	p := &testProtector{}
	RegisterSocketProtector(p)
	defer RegisterSocketProtector(nil)
	if !ProtectSocket(42) || p.got != 42 {
		t.Fatalf("socket protector got %d, want 42", p.got)
	}

	RegisterProcessFinder(testFinder{uid: 1234})
	defer RegisterProcessFinder(nil)
	if got := FindProcessConnection("tcp", "a", 1, "b", 2); got != 1234 {
		t.Fatalf("process finder = %d, want 1234", got)
	}
}
