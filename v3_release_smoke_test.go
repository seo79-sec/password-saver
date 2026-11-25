package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func checkV3RollbackReleasedEXE(t *testing.T, snapshot string, want *Vault) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	const releaseURL = "https://github.com/seo79-sec/password-saver/releases/download/v2.5.0/PasswordSaver-Standard-2.5.0-Windows-x64.zip"
	const releaseSHA = "a6de6c1e84099bb315d1642c7b2a57bfc7cbb3e1d3df0747920e7f7120f9e940"
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Get(releaseURL)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || fmt.Sprintf("%x", sha256.Sum256(archive)) != releaseSHA {
		t.Fatalf("release download failed verification (HTTP %d): %v", response.StatusCode, err)
	}
	zipped, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	file, err := zipped.Open("PasswordSaver/password-saver.exe")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := io.ReadAll(io.LimitReader(file, 32<<20))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	exe := filepath.Join(root, "password-saver.exe")
	if err := os.WriteFile(exe, executable, 0700); err != nil {
		t.Fatal(err)
	}
	localAppData := filepath.Join(root, "Local")
	profile := filepath.Join(localAppData, "PasswordSaver", "vaults", "default")
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	if err := secureStorageDirectory(profile); err != nil {
		t.Fatal(err)
	}
	for name, original := range map[string]string{dataFileV2: snapshot, vaultSelectorFile: vaultSelectorFile} {
		if err := writeFileAtomic(filepath.Join(profile, name), readPasswordChangeTestFile(t, original)); err != nil {
			t.Fatal(err)
		}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	child := exec.CommandContext(ctx, exe)
	child.Dir = root
	child.Env = append(os.Environ(),
		"LOCALAPPDATA="+localAppData,
		"APPDATA="+filepath.Join(root, "Roaming"),
		"WEBVIEW2_USER_DATA_FOLDER="+filepath.Join(root, "WebView2"),
		fmt.Sprintf("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-address=127.0.0.1 --remote-debugging-port=%d", port),
	)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = child.Wait() }()

	endpoint := fmt.Sprintf("http://127.0.0.1:%d/json/list", port)
	localClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{}}
	defer localClient.CloseIdleConnections()
	expression := fmt.Sprintf(`(async () => {
		const app = globalThis.go?.main?.App;
		if (!app) return null;
		const needsTOTP = await app.LoginV2(%q);
		if (!needsTOTP) throw new Error("export did not require TOTP");
		await app.Verify2FA(%q);
		return await app.GetAccounts();
	})()`, migrationTestPassword, currentCode(t, want.TwoFASecret))
	for ctx.Err() == nil {
		accounts, err := v3ReleasedEXEAccounts(ctx, deadline, localClient, endpoint, expression)
		if err != nil {
			t.Fatal(err)
		}
		if accounts != nil {
			if !slices.Equal(accounts, want.Accounts) {
				t.Fatal("release EXE did not return the expected records from the rollback")
			}
			t.Log("Verified published v2.5.0 EXE: opened the isolated rollback with TOTP and read the post-activation edit")
			if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
				log, err := os.OpenFile(summary, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fmt.Fprintln(log, "Published v2.5.0 Wails EXE opened the isolated rollback with TOTP and verified the post-activation edit."); err != nil {
					log.Close()
					t.Fatal(err)
				}
				log.Close()
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("released v2.5.0 EXE did not expose a WebView2 page with Go bindings")
}

func v3ReleasedEXEAccounts(ctx context.Context, deadline time.Time, client *http.Client, endpoint, expression string) ([]Account, error) {
	response, err := client.Get(endpoint)
	if err != nil {
		return nil, nil
	}
	var pages []struct {
		Type                 string
		WebSocketDebuggerURL string
	}
	err = json.NewDecoder(response.Body).Decode(&pages)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	for _, page := range pages {
		if page.Type != "page" || page.WebSocketDebuggerURL == "" {
			continue
		}
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, page.WebSocketDebuggerURL, nil)
		if err != nil {
			return nil, nil
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(deadline)
		_ = conn.SetWriteDeadline(deadline)
		if err := conn.WriteJSON(map[string]any{"id": 1, "method": "Runtime.evaluate", "params": map[string]any{
			"expression": expression, "awaitPromise": true, "returnByValue": true,
		}}); err != nil {
			return nil, err
		}
		var reply struct {
			Error  json.RawMessage
			Result struct {
				ExceptionDetails json.RawMessage
				Result           struct{ Value json.RawMessage }
			}
		}
		if err := conn.ReadJSON(&reply); err != nil {
			return nil, err
		}
		if reply.Error != nil || reply.Result.ExceptionDetails != nil {
			return nil, fmt.Errorf("WebView2 Go binding failed: %s %s", reply.Error, reply.Result.ExceptionDetails)
		}
		var accounts []Account
		if err := json.Unmarshal(reply.Result.Result.Value, &accounts); err != nil {
			return nil, err
		}
		return accounts, nil
	}
	return nil, nil
}
