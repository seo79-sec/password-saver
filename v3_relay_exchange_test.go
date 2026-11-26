package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncpair"
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncsession"
	"password-saver/internal/syncwire"
)

func TestV3RelayExchange(t *testing.T) {
	token := bytes.Repeat([]byte{0x5c}, 32)
	log := syncrelay.NewLog(8, 8*syncrelay.MaxEnvelopeSize)
	handler := syncrelay.NewHandler(log, sha256.Sum256(token))
	var posts atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && posts.Add(1) == 1 {
			// Let the real handler commit the first envelope before dropping its reply.
			reply := httptest.NewRecorder()
			handler.ServeHTTP(reply, r)
			if reply.Code == http.StatusOK {
				panic(http.ErrAbortHandler)
			}
			http.Error(w, http.StatusText(reply.Code), reply.Code)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	relayURL := "https://" + server.Listener.Addr().String()
	recordID := [16]byte{1}
	devices, parent := relayExchangeDevices(t, relayURL, recordID)
	var wires [2][]byte
	data := [2]string{"synthetic owner revision", "synthetic recipient revision"}
	// Both devices edit the same checkpoint parent while the relay is offline.
	for i := range devices {
		d := &devices[i]
		d.path = filepath.Join(t.TempDir(), "temporary replica.sqlite")
		d.key = [replicastore.KeySize]byte{byte(i + 1)}
		store, err := replicastore.Create(t.Context(), d.path, d.key)
		relayExchangeCheck(t, err)
		d.store = store
		t.Cleanup(func() { relayExchangeCheck(t, d.store.Close()) })
		initial := d.read(t)
		relayExchangeCheck(t, store.CommitExchange(t.Context(), d.confirmed, initial.Generation, nil, 0, 0))
		wire, err := syncsession.QueueLocal(t.Context(), store, d.confirmed, d.signer, "offline-edit", syncwire.LocalOperation{
			RecordID: recordID, Parents: [][32]byte{parent}, Action: syncmerge.Put, Data: []byte(data[i]),
		})
		relayExchangeCheck(t, err)
		wires[i] = wire
	}
	owner, recipient := &devices[0], &devices[1]
	offline := owner.read(t)
	relayExchangeCheck(t, owner.store.Close())
	reopened, err := replicastore.Open(t.Context(), owner.path, owner.key)
	relayExchangeCheck(t, err)
	owner.store = reopened
	if got := owner.read(t); !reflect.DeepEqual(got, offline) {
		t.Fatal("reopening changed the owner's offline snapshot or outbox")
	}
	assertRelayExchangeLog(t, log)

	server.StartTLS()
	var sessions [2]*syncsession.Session
	for i, d := range devices {
		client, err := syncrelay.NewClient(relayURL, base64.RawURLEncoding.EncodeToString(token), server.Client())
		relayExchangeCheck(t, err)
		sessions[i] = syncsession.NewSession(d.store, d.confirmed, client)
		sessions[i].SetAccess(true, true)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := sessions[0].RunOnce(ctx); err == nil {
		t.Fatal("expected the owner to lose its first POST reply")
	}
	if posts.Load() != 1 || !reflect.DeepEqual(owner.read(t), offline) {
		t.Fatal("losing the reply changed the owner's saved exchange state")
	}
	assertRelayExchangeLog(t, log, wires[0])
	relayExchangeCheck(t, sessions[0].RunOnce(ctx))
	if got := owner.read(t).State; posts.Load() != 2 || got.SentSequence != 1 || got.Cursor != 1 {
		t.Fatalf("retry progress: POSTs=%d sent=%d cursor=%d", posts.Load(), got.SentSequence, got.Cursor)
	}
	assertRelayExchangeLog(t, log, wires[0])

	relayExchangeCheck(t, sessions[1].RunOnce(ctx))
	relayExchangeCheck(t, sessions[0].RunOnce(ctx))
	assertRelayExchangeLog(t, log, wires[:]...)
	if posts.Load() != 3 {
		t.Fatalf("got %d POSTs, want two sends and one retry", posts.Load())
	}
	left, right := owner.read(t), recipient.read(t)
	if !reflect.DeepEqual(left.Snapshot, right.Snapshot) {
		t.Fatalf("snapshots did not converge: owner=%+v recipient=%+v", left.Snapshot, right.Snapshot)
	}
	wantRecord := hex.EncodeToString(recordID[:])
	if len(left.Snapshot) != 1 || left.Snapshot[0].ID != wantRecord || len(left.Snapshot[0].Versions) != 2 {
		t.Fatalf("expected both offline versions of the record: %+v", left.Snapshot)
	}
	versions := make(map[string]syncmerge.Operation)
	for _, version := range left.Snapshot[0].Versions {
		versions[version.ID] = version
	}
	for i, view := range []replicastore.ExchangeView{left, right} {
		digest := sha256.Sum256(wires[i])
		id, deviceID := hex.EncodeToString(digest[:]), devices[i].confirmed.Binding.DeviceID
		want := syncmerge.Operation{ID: id, RecordID: wantRecord, AuthorID: hex.EncodeToString(deviceID[:]),
			Parents: []string{hex.EncodeToString(parent[:])}, Action: syncmerge.Put, Data: []byte(data[i])}
		if !reflect.DeepEqual(versions[id], want) {
			t.Fatalf("replica %d's version differs: %+v", i, versions[id])
		}
		head := view.Heads[deviceID]
		if view.State.Cursor != 2 || head.Seq != 1 || head.Hash != digest || view.State.SentSequence != head.Seq ||
			len(view.State.Journal) != 2 || len(view.Pending) != 0 {
			t.Fatalf("replica %d exchange progress: cursor=%d sent=%d writer=%+v journal=%d waiting=%d",
				i, view.State.Cursor, view.State.SentSequence, head, len(view.State.Journal), len(view.Pending))
		}
	}
}

type relayExchangeDevice struct {
	confirmed replicastore.ExchangeContext
	signer    ed25519.PrivateKey
	store     *replicastore.Store
	path      string
	key       [replicastore.KeySize]byte
}

func (d *relayExchangeDevice) read(t *testing.T) replicastore.ExchangeView {
	t.Helper()
	view, err := d.store.ReadExchange(t.Context(), d.confirmed)
	relayExchangeCheck(t, err)
	return view
}

func relayExchangeDevices(t *testing.T, relayURL string, recordID [16]byte) ([2]relayExchangeDevice, [32]byte) {
	t.Helper()
	initial, fingerprint, ownerKeys, err := syncpair.NewSpace()
	relayExchangeCheck(t, err)
	base, err := syncpair.VerifyMembership(initial, nil, fingerprint)
	relayExchangeCheck(t, err)
	owner := base.Header.Members[0]
	ownerSigner := ownerKeys.DeviceSigningKey()
	oldKey := bytes.Repeat([]byte{0x31}, 32)
	source := syncwire.NewReceiver(base.Header.SpaceID, base.Header.Epoch, oldKey,
		map[[16]byte]ed25519.PublicKey{owner.DeviceID: owner.SigningPub[:]})
	seedWire, parent, err := syncwire.SealOperation(syncwire.Header{
		Type: 1, Version: 1, SpaceID: base.Header.SpaceID, Epoch: base.Header.Epoch, DeviceID: owner.DeviceID, Seq: 1,
	}, syncwire.LocalOperation{RecordID: recordID, Action: syncmerge.Put, Data: []byte("synthetic checkpoint record")}, oldKey, ownerSigner)
	relayExchangeCheck(t, err)
	if result := source.Receive(seedWire); result.Status != syncmerge.Applied {
		t.Fatalf("seed checkpoint: %+v", result)
	}
	checkpoint, err := source.MarshalCheckpoint()
	relayExchangeCheck(t, err)
	now := time.Unix(1_700_000_000, 0)
	request, requestHash, recipientKeys, err := syncpair.NewRequest(fingerprint, now)
	relayExchangeCheck(t, err)
	payload := syncpair.AnswerPayload{EpochKey: [32]byte{0x32}, Checkpoint: checkpoint}
	answer, err := ownerKeys.IssueAnswer(initial, request, requestHash, payload, now)
	relayExchangeCheck(t, err)
	membership, received, err := recipientKeys.OpenAnswer(answer, request, fingerprint, now)
	relayExchangeCheck(t, err)
	if received.EpochKey != payload.EpochKey || !bytes.Equal(received.Checkpoint, checkpoint) {
		t.Fatal("the verified pairing answer changed the epoch key or checkpoint")
	}
	membershipWire, err := membership.CanonicalBytes()
	relayExchangeCheck(t, err)
	verified, err := syncpair.VerifyMembership(membershipWire, initial, fingerprint)
	relayExchangeCheck(t, err)
	recipientSeed, _ := recipientKeys.PrivateBytes()
	defer clear(recipientSeed)
	signers := make(map[[16]byte]ed25519.PublicKey)
	for _, member := range verified.Header.Members {
		signers[member.DeviceID] = member.SigningPub[:]
	}
	deviceSigners := [2]ed25519.PrivateKey{ownerSigner, ed25519.NewKeyFromSeed(recipientSeed)}
	payloads := [2]syncpair.AnswerPayload{payload, received}
	var devices [2]relayExchangeDevice
	for i, member := range verified.Header.Members {
		p := payloads[i]
		devices[i] = relayExchangeDevice{signer: deviceSigners[i], confirmed: replicastore.ExchangeContext{
			Binding: replicastore.ExchangeBinding{SpaceID: verified.Header.SpaceID, Epoch: verified.Header.Epoch, DeviceID: member.DeviceID,
				MembershipHash: sha256.Sum256(membershipWire), CheckpointHash: sha256.Sum256(p.Checkpoint), RelayURL: relayURL},
			Checkpoint: p.Checkpoint, EpochKey: p.EpochKey[:], Signers: signers,
		}}
	}
	return devices, parent
}

func assertRelayExchangeLog(t *testing.T, log *syncrelay.Log, wires ...[]byte) {
	t.Helper()
	entries, err := log.List(0, syncrelay.MaxPageSize)
	relayExchangeCheck(t, err)
	if len(entries) != len(wires) {
		t.Fatalf("relay has %d entries, want %d", len(entries), len(wires))
	}
	for i, entry := range entries {
		if entry.Cursor != uint64(i+1) || !bytes.Equal(entry.Wire, wires[i]) {
			t.Fatalf("relay entry %d has different bytes or cursor", i)
		}
	}
}

func relayExchangeCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
