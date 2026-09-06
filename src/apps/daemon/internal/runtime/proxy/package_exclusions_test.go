package proxy

import "testing"

func TestAndroidVPNExclusionManager(t *testing.T) {
	mgr := NewAndroidVPNExclusionManager()

	packages := []string{"com.android.chrome", "com.google.android.youtube", "   "}
	mgr.SetExcludedPackages(packages)

	if !mgr.IsPackageExcluded("com.android.chrome") {
		t.Error("expected com.android.chrome to be excluded")
	}

	if !mgr.IsPackageExcluded("com.google.android.youtube") {
		t.Error("expected com.google.android.youtube to be excluded")
	}

	if mgr.IsPackageExcluded("com.example.app") {
		t.Error("expected com.example.app to NOT be excluded")
	}

	excludeList := mgr.GetExcludeList()
	if len(excludeList) != 2 {
		t.Errorf("expected exclude list length 2, got %d", len(excludeList))
	}
}
