package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	cryptov2 "password-saver/crypto/v2"
	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncwire"
)

func TestExportV3DisconnectedCopy(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		name := "offline edit"
		if conflict {
			name = "conflicting versions"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			require := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			const password, secret = "export test password", "JBSWY3DPEHPK3PXP"
			dir := t.TempDir()
			engine, err := cryptov2.NewEngine(cryptov2.Options{})
			require(err)
			recordID := [16]byte{1}
			original := Account{ID: hex.EncodeToString(recordID[:]), Password: "original"}
			plain, err := json.Marshal(&Vault{Accounts: []Account{original}, TwoFAEnabled: true, TwoFASecret: secret})
			require(err)
			source, recovery, err := engine.EncryptWithRecoveryKey(password, plain)
			wipeBytes(plain)
			require(err)
			require(writeFileAtomic(filepath.Join(dir, v3SourceFile), source))
			session, reopened, err := engine.Unlock(password, source)
			wipeBytes(reopened)
			require(err)
			defer session.Close()
			candidate := v3MigrationCandidate{profile: dir}
			store, err := replicastore.Create(ctx, candidate.replicaPath(), [replicastore.KeySize]byte{2})
			require(err)
			t.Cleanup(func() { _ = store.Close() })
			var opened v3OpenedCopy
			opened.marker.Version, opened.marker.ID, opened.marker.Source = 1, store.Identity(), sha256.Sum256(source)
			opened.marker.KeyWrap, err = session.WrapReplicaKey(opened.marker.ID, [replicastore.KeySize]byte{2})
			require(err)
			markerPath, marker := filepath.Join(dir, v3MarkerFile), opened.marker.encode()
			require(writeFileAtomic(markerPath, marker))

			var requests atomic.Int32
			relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(relay.Close)
			ownerPub, owner, err := ed25519.GenerateKey(rand.Reader)
			require(err)
			peerPub, peer, err := ed25519.GenerateKey(rand.Reader)
			require(err)
			ownerID, peerID, space := [16]byte{1}, [16]byte{2}, [16]byte{3}
			epochKey := [32]byte{1}
			checkpoint, err := syncwire.NewReceiver(space, 1, epochKey[:], nil).MarshalCheckpoint()
			require(err)
			confirmed := replicastore.ExchangeContext{
				Binding: replicastore.ExchangeBinding{SpaceID: space, DeviceID: ownerID, Epoch: 2, RelayURL: relay.URL,
					MembershipHash: [32]byte{1}, CheckpointHash: sha256.Sum256(checkpoint)},
				Checkpoint: checkpoint, EpochKey: epochKey[:],
				Signers: map[[16]byte]ed25519.PublicKey{ownerID: ownerPub, peerID: peerPub},
			}
			edit := original
			edit.Password = "offline edit"
			data, err := json.Marshal(edit)
			require(err)
			put := syncwire.LocalOperation{RecordID: recordID, Action: syncmerge.Put, Data: data}
			header := syncwire.Header{Type: 1, Version: 1, SpaceID: space, Epoch: 2, DeviceID: ownerID, Seq: 1}
			wire, hash, err := syncwire.SealOperation(header, put, epochKey[:], owner)
			require(err)
			entries := []replicastore.ExchangeEnvelope{{Wire: wire, CommandID: "offline edit", CommandHash: hash, Sequence: 1}}
			if conflict {
				header.DeviceID = peerID
				other, _, err := syncwire.SealOperation(header, syncwire.LocalOperation{RecordID: recordID, Action: syncmerge.Delete}, epochKey[:], peer)
				require(err)
				entries = append(entries, replicastore.ExchangeEnvelope{Wire: other})
			}
			read := func() replicastore.ExchangeView {
				t.Helper()
				view, err := store.ReadExchange(ctx, confirmed)
				require(err)
				return view
			}
			require(store.CommitExchange(ctx, confirmed, read().Generation, entries, 0, 7))
			code, err := totp.GenerateCode(secret, time.Now())
			require(err)
			destination := filepath.Join(dir, "vault-disconnected.v2.enc")
			assertRejected := func(password, code string, expected error) {
				t.Helper()
				path, err := exportV3DisconnectedCopy(ctx, dir, engine, password, code, confirmed)
				if err == nil || (expected != nil && !errors.Is(err, expected)) || path != "" {
					t.Fatalf("rejected export returned %q, %v", path, err)
				}
				if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected export created a file: %v", err)
				}
			}
			assertRejected(password, code, ErrVaultActivationDenied)
			require(store.DisconnectExchange(ctx, confirmed.Binding, read().Generation))
			before := read()
			assertRejected("wrong password", code, nil)
			assertRejected(password, "invalid code", nil)
			if conflict {
				assertRejected(password, code, errV3MigrationConflict)
			} else {
				path, err := exportV3DisconnectedCopy(ctx, dir, engine, password, code, confirmed)
				require(err)
				if path != destination {
					t.Fatalf("unexpected export path %q", path)
				}
				vault, err := readV2VaultAt(path, engine, password)
				require(err)
				defer wipeVault(vault)
				if !vault.TwoFAEnabled || vault.TwoFASecret != secret || !reflect.DeepEqual(vault.Accounts, []Account{edit}) {
					t.Fatal("export lost the applied offline edit or local TOTP")
				}
				exported, err := os.ReadFile(path)
				require(err)
				var oldWire, newWire cryptov2.Container
				require(json.Unmarshal(source, &oldWire))
				require(json.Unmarshal(exported, &newWire))
				if oldWire.Recovery == nil || !reflect.DeepEqual(oldWire.Recovery, newWire.Recovery) {
					t.Fatal("export changed the original recovery slot")
				}
				recovered, err := engine.DecryptWithRecoveryKey(recovery, exported)
				defer wipeBytes(recovered)
				require(err)
				var recoveredVault Vault
				require(json.Unmarshal(recovered, &recoveredVault))
				defer wipeVault(&recoveredVault)
				if !reflect.DeepEqual(&recoveredVault, vault) {
					t.Fatal("recovery returned different records or TOTP")
				}
				if path, err := exportV3DisconnectedCopy(ctx, dir, engine, password, code, confirmed); err == nil || path != "" {
					t.Fatal("export overwrote the existing file")
				}
				after, err := os.ReadFile(destination)
				require(err)
				if !bytes.Equal(exported, after) {
					t.Fatal("existing export changed on a second attempt")
				}
			}
			currentMarker, err := os.ReadFile(markerPath)
			require(err)
			if !bytes.Equal(marker, currentMarker) || !reflect.DeepEqual(read(), before) || requests.Load() != 0 {
				t.Fatal("export changed the marker or replica, or contacted the relay")
			}
		})
	}
}
