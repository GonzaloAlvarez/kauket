package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gogitcfg "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func enrollClientHome(t *testing.T, bareURL, name string) (clientHome string, requestID string) {
	t.Helper()
	a, fake, home := newTestApp(t)
	flags := &enrollFlags{
		requests: []string{"ssh"},
		name:     name,
		remote:   bareURL,
		yes:      true,
	}
	if err := runEnroll(context.Background(), a, flags); err != nil {
		t.Fatalf("enroll %s: %v", name, err)
	}
	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "created enrollment request rq_") {
			requestID = strings.TrimPrefix(line, "created enrollment request ")
			requestID = strings.TrimSpace(requestID)
			break
		}
	}
	if requestID == "" {
		t.Fatalf("could not find request id in enroll output: %v", fake.Lines)
	}
	return home, requestID
}

func newApproveAdminApp(t *testing.T, home string) (*app.App, *ui.Fake) {
	t.Helper()
	f := &ui.Fake{}
	a := &app.App{
		UI:   f,
		Home: home,
	}
	return a, f
}

func TestApproveSingleRequest(t *testing.T) {
	adminHome, bareURL := setupAdminStore(t)
	clientHome, _ := enrollClientHome(t, bareURL, "machine2")

	adminApp, fake := newApproveAdminApp(t, adminHome)
	flags := &approveFlags{all: true, yes: true}
	if err := runApprove(context.Background(), adminApp, flags); err != nil {
		t.Fatalf("approve: %v", err)
	}

	var approveLine string
	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "request ") && strings.HasSuffix(line, " approved") && !strings.Contains(line, "dry-run") {
			approveLine = line
			break
		}
	}
	if approveLine == "" {
		t.Fatalf("missing 'request N approved' line; got: %v", fake.Lines)
	}
	if approveLine != "request 1 approved" {
		t.Fatalf("expected 'request 1 approved', got %q", approveLine)
	}

	wantPrefix := []string{"syncing store", "fetching pending requests", "", "Pending requests:", ""}
	if len(fake.Lines) < len(wantPrefix) {
		t.Fatalf("not enough output lines: %v", fake.Lines)
	}
	for i, w := range wantPrefix {
		if fake.Lines[i] != w {
			t.Fatalf("output line %d: want %q got %q (all: %v)", i, w, fake.Lines[i], fake.Lines)
		}
	}
	listing := fake.Lines[len(wantPrefix)]
	if !strings.HasPrefix(listing, "1. request machine2 ") {
		t.Fatalf("listing line should start with '1. request machine2 ', got %q", listing)
	}
	if !strings.HasSuffix(listing, " ssh") {
		t.Fatalf("listing line should end with ' ssh', got %q", listing)
	}

	vault := loadAdminVault(t, adminHome)
	clientCfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client: %v", err)
	}
	host, ok := vault.Hosts[clientCfg.Host.ID]
	if !ok {
		t.Fatalf("vault missing host %s; hosts: %v", clientCfg.Host.ID, vault.Hosts)
	}
	if host.DisplayName != "machine2" {
		t.Fatalf("host display name: %q", host.DisplayName)
	}
	if len(host.GrantedProfiles) != 1 || host.GrantedProfiles[0] != "ssh" {
		t.Fatalf("granted profiles: %v", host.GrantedProfiles)
	}
	if host.AgeRecipient == "" {
		t.Fatalf("host age recipient empty")
	}
	if host.DeployKeyFingerprint == "" || !strings.HasPrefix(host.DeployKeyFingerprint, "SHA256:") {
		t.Fatalf("deploy key fingerprint: %q", host.DeployKeyFingerprint)
	}

	bundlePath := filepath.Join(config.RepoDir(adminHome), "bundles", clientCfg.Host.ID+".age")
	ct, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	hostIDPath := filepath.Join(clientHome, "identities", "host.txt")
	if _, err := bundle.DecodeHostBundle(ct, agebox.FileIdentityProvider{Path: hostIDPath}); err != nil {
		t.Fatalf("host identity should decrypt bundle: %v", err)
	}
	adminIDPath := config.AdminIdentityPath(adminHome)
	if _, err := bundle.DecodeHostBundle(ct, agebox.FileIdentityProvider{Path: adminIDPath}); err != nil {
		t.Fatalf("admin identity should also decrypt bundle (admin-recovery invariant): %v", err)
	}

	if refs := collectEnrollRequestRefs(t, bareURL); len(refs) != 0 {
		t.Fatalf("expected zero request refs after approve, got %v", refs)
	}

	osHostname, _ := os.Hostname()
	checkoutRepo := config.RepoDir(adminHome)
	leakErrs := scanForLiteral(t, checkoutRepo, osHostname)
	if osHostname != "" && len(leakErrs) > 0 {
		t.Fatalf("os.Hostname literal leak in admin checkout: %v", leakErrs)
	}
}

func scanForLiteral(t *testing.T, root, needle string) []string {
	t.Helper()
	if needle == "" {
		return nil
	}
	var found []string
	needleBytes := []byte(needle)
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if bytes.Contains(data, needleBytes) {
			found = append(found, path)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}
	return found
}

func TestApproveDryRun(t *testing.T) {
	adminHome, bareURL := setupAdminStore(t)
	clientHome, _ := enrollClientHome(t, bareURL, "machine2")

	bundlesDir := filepath.Join(config.RepoDir(adminHome), "bundles")
	beforeEntries, _ := os.ReadDir(bundlesDir)
	beforeFiles := map[string]struct{}{}
	for _, e := range beforeEntries {
		beforeFiles[e.Name()] = struct{}{}
	}

	vaultPath := filepath.Join(config.RepoDir(adminHome), "admin", "vault.age")
	vaultBefore, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault before: %v", err)
	}

	refsBefore := collectEnrollRequestRefs(t, bareURL)
	if len(refsBefore) != 1 {
		t.Fatalf("setup: want 1 ref, got %v", refsBefore)
	}

	adminApp, fake := newApproveAdminApp(t, adminHome)
	flags := &approveFlags{all: true, yes: true, dryRun: true}
	if err := runApprove(context.Background(), adminApp, flags); err != nil {
		t.Fatalf("approve dry-run: %v", err)
	}

	foundDry := false
	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "request ") && strings.Contains(line, "dry-run") {
			foundDry = true
			break
		}
	}
	if !foundDry {
		t.Fatalf("expected dry-run marker in output: %v", fake.Lines)
	}

	vaultAfter, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault after: %v", err)
	}
	if !bytes.Equal(vaultBefore, vaultAfter) {
		t.Fatalf("vault changed in dry-run")
	}

	clientCfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client: %v", err)
	}
	bundlePath := filepath.Join(bundlesDir, clientCfg.Host.ID+".age")
	if _, err := os.Stat(bundlePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle should not exist after dry-run; stat err: %v", err)
	}

	refsAfter := collectEnrollRequestRefs(t, bareURL)
	if len(refsAfter) != 1 {
		t.Fatalf("request branch should remain after dry-run, got %v", refsAfter)
	}
}

func TestApproveRejectsAlreadyApproved(t *testing.T) {
	adminHome, bareURL := setupAdminStore(t)
	enrollClientHome(t, bareURL, "machine2")

	adminApp, fake := newApproveAdminApp(t, adminHome)
	if err := runApprove(context.Background(), adminApp, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("first approve: %v", err)
	}

	hasApproved := false
	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "request ") && strings.HasSuffix(line, " approved") {
			hasApproved = true
			break
		}
	}
	if !hasApproved {
		t.Fatalf("first approve missing approval line: %v", fake.Lines)
	}

	fake.Lines = nil
	fake.Errors = nil
	if err := runApprove(context.Background(), adminApp, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("second approve: %v", err)
	}

	foundNothing := false
	for _, line := range fake.Lines {
		if line == "nothing to approve" {
			foundNothing = true
			break
		}
	}
	if !foundNothing {
		t.Fatalf("expected 'nothing to approve' on second run, got: %v", fake.Lines)
	}
}

func TestApproveRejectsInvalidSignature(t *testing.T) {
	adminHome, bareURL := setupAdminStore(t)
	enrollClientHome(t, bareURL, "machine2")

	refs := collectEnrollRequestRefs(t, bareURL)
	if len(refs) != 1 {
		t.Fatalf("setup: want 1 ref, got %v", refs)
	}
	branchRef := refs[0]
	adminIDPath := config.AdminIdentityPath(adminHome)
	repoMeta, err := readRepoJSON(t, adminHome)
	if err != nil {
		t.Fatalf("repo.json: %v", err)
	}
	adminRecips := make([]string, 0, len(repoMeta.AdminRecipients))
	for _, r := range repoMeta.AdminRecipients {
		adminRecips = append(adminRecips, r.Recipient)
	}
	if err := tamperRequestSignature(t, bareURL, branchRef, adminIDPath, adminRecips); err != nil {
		t.Fatalf("tamper request: %v", err)
	}

	adminApp, fake := newApproveAdminApp(t, adminHome)
	if err := runApprove(context.Background(), adminApp, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	foundWarn := false
	for _, e := range fake.Errors {
		if strings.Contains(strings.ToLower(e), "signature") {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Fatalf("expected signature warning; errors: %v lines: %v", fake.Errors, fake.Lines)
	}

	approved := false
	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "request ") && strings.HasSuffix(line, " approved") && !strings.Contains(line, "dry-run") {
			approved = true
			break
		}
	}
	if approved {
		t.Fatalf("tampered request should not be approved; lines: %v", fake.Lines)
	}

	vault := loadAdminVault(t, adminHome)
	if len(vault.Hosts) != 0 {
		t.Fatalf("vault should have no hosts after tampered approve, got %v", vault.Hosts)
	}
}

func TestApproveRejectsMismatchedStoreID(t *testing.T) {
	adminHome, bareURL := setupAdminStore(t)

	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	_ = cfg

	repoMeta, err := readRepoJSON(t, adminHome)
	if err != nil {
		t.Fatalf("read repo.json: %v", err)
	}
	adminRecips := make([]string, 0, len(repoMeta.AdminRecipients))
	for _, r := range repoMeta.AdminRecipients {
		adminRecips = append(adminRecips, r.Recipient)
	}

	clientHome, _ := enrollFakeRequest(t, bareURL, adminRecips, "ks_wrongstoreidaaaa")
	_ = clientHome

	adminApp, fake := newApproveAdminApp(t, adminHome)
	if err := runApprove(context.Background(), adminApp, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	foundWarn := false
	for _, e := range fake.Errors {
		if strings.Contains(e, "store_id") {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Fatalf("expected store_id mismatch warning; errors: %v lines: %v", fake.Errors, fake.Lines)
	}

	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "request ") && strings.HasSuffix(line, " approved") {
			t.Fatalf("mismatched store_id should not be approved; lines: %v", fake.Lines)
		}
	}
}

func TestApproveSpecificRequest(t *testing.T) {
	adminHome, bareURL := setupAdminStore(t)
	clientA, requestA := enrollClientHome(t, bareURL, "machineA")
	clientB, requestB := enrollClientHome(t, bareURL, "machineB")
	_ = clientB

	cfgA, err := config.LoadClient(clientA)
	if err != nil {
		t.Fatalf("load A: %v", err)
	}

	adminApp, fake := newApproveAdminApp(t, adminHome)
	flags := &approveFlags{request: requestA, yes: true}
	if err := runApprove(context.Background(), adminApp, flags); err != nil {
		t.Fatalf("approve: %v", err)
	}

	approvedCount := 0
	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "request ") && strings.HasSuffix(line, " approved") && !strings.Contains(line, "dry-run") {
			approvedCount++
		}
	}
	if approvedCount != 1 {
		t.Fatalf("expected 1 approval, got %d; lines: %v", approvedCount, fake.Lines)
	}

	vault := loadAdminVault(t, adminHome)
	if _, ok := vault.Hosts[cfgA.Host.ID]; !ok {
		t.Fatalf("vault missing host A %s; hosts: %v", cfgA.Host.ID, vault.Hosts)
	}
	if len(vault.Hosts) != 1 {
		t.Fatalf("expected exactly 1 host approved, got %d: %v", len(vault.Hosts), vault.Hosts)
	}
	if _, ok := vault.Requests[requestA]; !ok {
		t.Fatalf("vault missing request A %s", requestA)
	}
	if _, ok := vault.Requests[requestB]; ok {
		t.Fatalf("vault should not contain request B %s yet", requestB)
	}

	refs := collectEnrollRequestRefs(t, bareURL)
	if len(refs) != 1 {
		t.Fatalf("expected B's request branch to remain, got %v", refs)
	}
	if !strings.Contains(refs[0], requestB) {
		t.Fatalf("remaining ref should be request B (%s), got %q", requestB, refs[0])
	}
}

func tamperRequestSignature(t *testing.T, bareURL, refName, adminIDPath string, adminRecipients []string) error {
	t.Helper()
	bareDir := strings.TrimPrefix(bareURL, "file://")
	repo, err := gogit.PlainOpen(bareDir)
	if err != nil {
		return fmt.Errorf("open bare: %w", err)
	}
	ref, err := repo.Reference(plumbing.ReferenceName(refName), true)
	if err != nil {
		return fmt.Errorf("ref: %w", err)
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("tree: %w", err)
	}
	var (
		filePath string
		fileHash plumbing.Hash
	)
	if err := tree.Files().ForEach(func(f *object.File) error {
		if strings.HasPrefix(f.Name, "requests/") && strings.HasSuffix(f.Name, ".age") {
			filePath = f.Name
			fileHash = f.Hash
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk: %w", err)
	}
	if filePath == "" {
		return fmt.Errorf("no request file found in tree")
	}
	blob, err := repo.BlobObject(fileHash)
	if err != nil {
		return fmt.Errorf("blob: %w", err)
	}
	r, err := blob.Reader()
	if err != nil {
		return fmt.Errorf("reader: %w", err)
	}
	ct, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	padded, err := agebox.Decrypt(ct, agebox.FileIdentityProvider{Path: adminIDPath})
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	plaintext, err := agebox.Unwrap(padded)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}
	var req model.Request
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if req.Signature == nil {
		return fmt.Errorf("expected signed request")
	}
	sigBytes, err := decodeB64(req.Signature.SignatureBase64)
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	if len(sigBytes) == 0 {
		return fmt.Errorf("empty signature")
	}
	sigBytes[0] ^= 0xFF
	req.Signature.SignatureBase64 = encodeB64(sigBytes)
	tampered, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("re-marshal: %w", err)
	}
	repadded, err := agebox.Wrap(tampered, 0)
	if err != nil {
		return fmt.Errorf("re-wrap: %w", err)
	}
	newCT, err := agebox.Encrypt(repadded, agebox.X25519RecipientProvider{Strings: adminRecipients})
	if err != nil {
		return fmt.Errorf("re-encrypt: %w", err)
	}

	st := repo.Storer
	newBlob := st.NewEncodedObject()
	newBlob.SetType(plumbing.BlobObject)
	bw, err := newBlob.Writer()
	if err != nil {
		return fmt.Errorf("new blob writer: %w", err)
	}
	if _, err := bw.Write(newCT); err != nil {
		_ = bw.Close()
		return fmt.Errorf("write blob: %w", err)
	}
	_ = bw.Close()
	newBlobHash, err := st.SetEncodedObject(newBlob)
	if err != nil {
		return fmt.Errorf("store blob: %w", err)
	}

	idx := strings.Index(filePath, "/")
	dirName := filePath[:idx]
	fileName := filePath[idx+1:]
	subtree := object.Tree{Entries: []object.TreeEntry{{
		Name: fileName,
		Mode: filemode.Regular,
		Hash: newBlobHash,
	}}}
	subObj := st.NewEncodedObject()
	if err := subtree.Encode(subObj); err != nil {
		return fmt.Errorf("encode subtree: %w", err)
	}
	subHash, err := st.SetEncodedObject(subObj)
	if err != nil {
		return fmt.Errorf("store subtree: %w", err)
	}

	rootTree := object.Tree{Entries: []object.TreeEntry{{
		Name: dirName,
		Mode: filemode.Dir,
		Hash: subHash,
	}}}
	rootObj := st.NewEncodedObject()
	if err := rootTree.Encode(rootObj); err != nil {
		return fmt.Errorf("encode root: %w", err)
	}
	rootHash, err := st.SetEncodedObject(rootObj)
	if err != nil {
		return fmt.Errorf("store root: %w", err)
	}

	newCommit := object.Commit{
		Author:    commit.Author,
		Committer: commit.Committer,
		Message:   commit.Message,
		TreeHash:  rootHash,
	}
	commitObj := st.NewEncodedObject()
	if err := newCommit.Encode(commitObj); err != nil {
		return fmt.Errorf("encode commit: %w", err)
	}
	newCommitHash, err := st.SetEncodedObject(commitObj)
	if err != nil {
		return fmt.Errorf("store commit: %w", err)
	}

	newRef := plumbing.NewHashReference(plumbing.ReferenceName(refName), newCommitHash)
	if err := repo.Storer.SetReference(newRef); err != nil {
		return fmt.Errorf("update ref: %w", err)
	}
	return nil
}

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func readRepoJSON(t *testing.T, adminHome string) (*repoJSON, error) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(config.RepoDir(adminHome), "repo.json"))
	if err != nil {
		return nil, err
	}
	var rj repoJSON
	if err := json.Unmarshal(data, &rj); err != nil {
		return nil, err
	}
	return &rj, nil
}

func enrollFakeRequest(t *testing.T, bareURL string, adminRecipients []string, storeID string) (clientHome string, requestID string) {
	t.Helper()
	clientHome = t.TempDir()
	if err := config.EnsureIdentitiesDir(clientHome); err != nil {
		t.Fatalf("identities dir: %v", err)
	}
	if err := config.EnsureGitDir(clientHome); err != nil {
		t.Fatalf("git dir: %v", err)
	}

	hostIdent, err := agebox.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen host identity: %v", err)
	}
	hostIdentityPath := config.HostIdentityPath(clientHome)
	if err := os.WriteFile(hostIdentityPath, []byte(hostIdent.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write host identity: %v", err)
	}

	deployKeyPath := config.DeployKeyPath(clientHome)
	deployPubPath := config.DeployKeyPubPath(clientHome)
	deployPub, err := ensureDeployKey(deployKeyPath, deployPubPath)
	if err != nil {
		t.Fatalf("deploy key: %v", err)
	}

	hostID := model.NewHostID()
	requestID = model.NewRequestID()
	req := model.Request{
		Schema:    1,
		StoreID:   storeID,
		RequestID: requestID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Host: model.RequestHost{
			ID:                 hostID,
			DisplayName:        "fakehost",
			ReportedHostname:   "fakehost.example",
			OS:                 "linux",
			Arch:               "amd64",
			AgeRecipient:       hostIdent.Recipient().String(),
			GitDeployPublicKey: deployPub,
		},
		Requested: model.RequestedItems{Profiles: []string{"ssh"}},
	}
	signer := bundle.Ed25519FileSigner{Path: deployKeyPath}
	ct, err := bundle.EncodeRequest(req, signer, agebox.X25519RecipientProvider{Strings: adminRecipients})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}

	pushDir := t.TempDir()
	repoPath := filepath.Join(pushDir, "repo")
	if err := os.MkdirAll(repoPath, 0o700); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	repo, err := gogit.PlainInit(repoPath, false)
	if err != nil {
		t.Fatalf("plain init: %v", err)
	}
	if _, err := repo.CreateRemote(&gogitcfg.RemoteConfig{Name: "origin", URLs: []string{bareURL}}); err != nil {
		t.Fatalf("create remote: %v", err)
	}

	st := repo.Storer
	blob := st.NewEncodedObject()
	blob.SetType(plumbing.BlobObject)
	bw, err := blob.Writer()
	if err != nil {
		t.Fatalf("blob writer: %v", err)
	}
	if _, err := bw.Write(ct); err != nil {
		t.Fatalf("blob write: %v", err)
	}
	_ = bw.Close()
	blobHash, err := st.SetEncodedObject(blob)
	if err != nil {
		t.Fatalf("set blob: %v", err)
	}

	inner := object.Tree{Entries: []object.TreeEntry{{
		Name: requestID + ".age",
		Mode: filemode.Regular,
		Hash: blobHash,
	}}}
	innerObj := st.NewEncodedObject()
	if err := inner.Encode(innerObj); err != nil {
		t.Fatalf("encode inner: %v", err)
	}
	innerHash, err := st.SetEncodedObject(innerObj)
	if err != nil {
		t.Fatalf("set inner: %v", err)
	}
	root := object.Tree{Entries: []object.TreeEntry{{
		Name: "requests",
		Mode: filemode.Dir,
		Hash: innerHash,
	}}}
	ro := st.NewEncodedObject()
	if err := root.Encode(ro); err != nil {
		t.Fatalf("encode root: %v", err)
	}
	rootHash, err := st.SetEncodedObject(ro)
	if err != nil {
		t.Fatalf("set root: %v", err)
	}
	sig := object.Signature{Name: "kauket fake", Email: "fake@kauket.local", When: time.Now()}
	commit := object.Commit{
		Author:    sig,
		Committer: sig,
		Message:   "kauket: submit request",
		TreeHash:  rootHash,
	}
	co := st.NewEncodedObject()
	if err := commit.Encode(co); err != nil {
		t.Fatalf("encode commit: %v", err)
	}
	commitHash, err := st.SetEncodedObject(co)
	if err != nil {
		t.Fatalf("set commit: %v", err)
	}

	branch := "request/" + requestID
	ref := plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), commitHash)
	if err := repo.Storer.SetReference(ref); err != nil {
		t.Fatalf("set ref: %v", err)
	}
	if err := repo.Push(&gogit.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []gogitcfg.RefSpec{gogitcfg.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", branch, branch))},
	}); err != nil {
		t.Fatalf("push: %v", err)
	}
	return clientHome, requestID
}
