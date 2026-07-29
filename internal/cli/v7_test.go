package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/config"
)

func TestPurgeV1(t *testing.T) {
	adminApp, adminFake, adminBase, clientApp, _, _, keyContent := migratedStoreFixture(t)
	adminHome := config.RoleHome(adminBase, config.RoleAdmin)
	repoDir := config.RepoDir(adminHome)

	if _, err := os.Stat(filepath.Join(repoDir, "admin", "vault.age")); err != nil {
		t.Fatalf("frozen vault missing pre-purge: %v", err)
	}

	adminFake.Lines = nil
	if err := runMigrateStore(context.Background(), adminApp, &migrateStoreFlags{purgeV1: true, yes: true}); err == nil {
		t.Fatalf("runMigrateStore ignores purgeV1; must go through runPurgeV1")
	}
	if err := runPurgeV1(context.Background(), adminApp, &migrateStoreFlags{purgeV1: true, yes: true}); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if !strings.Contains(strings.Join(adminFake.Lines, "\n"), "purged v1") {
		t.Fatalf("purge output: %v", adminFake.Lines)
	}

	for _, p := range []string{"repo.json", "admin", "bundles"} {
		if _, err := os.Stat(filepath.Join(repoDir, p)); !os.IsNotExist(err) {
			t.Fatalf("v1 path %s still present after purge: %v", p, err)
		}
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "ssh.main_private_key"); err != nil {
			t.Fatalf("client get after purge: %v", err)
		}
	})
	if string(out) != string(keyContent) {
		t.Fatalf("client content after purge mismatch")
	}
	if err := runVerify(context.Background(), adminApp, true); err != nil {
		t.Fatalf("verify after purge: %v", err)
	}
}
