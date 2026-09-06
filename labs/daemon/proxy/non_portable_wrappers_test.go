package proxy

import (
	"context"
	"testing"
	"time"
)

func TestNonPortableWrappers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	t.Run("NonExistentRouteScript", func(t *testing.T) {
		err := RunRouteSetupScript(ctx, "non_existent_script.bat")
		if err == nil {
			t.Error("expected error for non-existent script, got nil")
		}
	})

	t.Run("NonExistentGUI", func(t *testing.T) {
		err := LaunchSystemTrayGUI(ctx, "non_existent_gui.exe")
		if err == nil {
			t.Error("expected error for non-existent GUI binary, got nil")
		}
	})

	t.Run("NonExistentScraper", func(t *testing.T) {
		err := RunPythonScraper(ctx, "non_existent_scraper.py")
		if err == nil {
			t.Error("expected error for non-existent scraper, got nil")
		}
	})
}
