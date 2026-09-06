package abimanifest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestValidateAcceptsMatchingAuthority(t *testing.T) {
	root := writeFixture(t, 3, "Scan = 1,\n    RouteUpdate = 2,")
	result, err := Validate(Options{RepositoryRoot: root})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.ABIMajor != 3 || result.Operations != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestValidateRejectsOperationDrift(t *testing.T) {
	root := writeFixture(t, 3, "Scan = 1,\n    RouteUpdate = 9,")
	_, err := Validate(Options{RepositoryRoot: root})
	if err == nil || !strings.Contains(err.Error(), "route_update") {
		t.Fatalf("Validate() error = %v, want route_update mismatch", err)
	}
}

func TestValidateRejectsVersionDrift(t *testing.T) {
	root := writeFixture(t, 4, "Scan = 1,\n    RouteUpdate = 2,")
	_, err := Validate(Options{RepositoryRoot: root})
	if err == nil || !strings.Contains(err.Error(), "LUMICORE_ABI_VERSION") {
		t.Fatalf("Validate() error = %v, want version mismatch", err)
	}
}

func writeFixture(t *testing.T, rustMajor int, operations string) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("governance/conductor/abi/manifest-v1.json", `{"schema_version":1,"abi":{"major":3,"minor":0,"patch":0},"envelope":{"request":"request","status":"status","ownership":"ownership"},"operations":[{"id":1,"name":"scan","status":"implemented"},{"id":2,"name":"route_update","status":"declared_not_implemented"}]}`)
	write("src/packages/lumicore/src/ffi/envelope.rs", "pub const LUMICORE_ABI_VERSION: u16 = "+strconv.Itoa(rustMajor)+";\n#[repr(C)] pub struct FfiEnvelope {}\n#[repr(C)] pub struct FfiStatus {}\npub enum OpCode {\n    "+operations+"\n}\n")
	write("src/packages/lumicore/src/ffi/version.rs", "pub const ABI_MAJOR: u16 = "+strconv.Itoa(rustMajor)+";\npub const ABI_MINOR: u16 = 0;\npub const ABI_PATCH: u16 = 0;\n")
	return root
}
