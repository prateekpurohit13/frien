package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/revocation"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// cmdRevoke dispatches the two revocation subcommands. Signing and
// submission are deliberately separate steps run as separate processes: sign
// never needs a socket (it can run on an air-gapped operator machine holding
// the operator private key, which docs/security.md says never touches a
// running node), and submit never needs the private key (it only ever
// forwards already-signed bytes to a node's admin API).
func cmdRevoke(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: frienctl revoke sign|submit ...")
	}
	switch args[0] {
	case "sign":
		return cmdRevokeSign(args[1:])
	case "submit":
		return cmdRevokeSubmit(args[1:])
	default:
		return fmt.Errorf("unknown revoke subcommand %q (want sign or submit)", args[0])
	}
}

// cmdRevokeSign builds and signs a revocation entirely offline: a
// RevocationRecord signed with the operator key (internal/revocation.Build),
// wrapped in an OperationEnvelope whose own envelope-level signature is what
// gossip.Engine.ingest actually verifies against the pinned operator key
// (see internal/gossip's applyRevocation doc comment on why the envelope
// field is what's checked, not the payload's claimed signed_by). The result
// is written base64-encoded so it can be copied over an airgap and pasted
// or piped into `revoke submit` without worrying about binary-safe transport.
func cmdRevokeSign(args []string) error {
	fs := flag.NewFlagSet("revoke sign", flag.ContinueOnError)
	nodeID := fs.String("node-id", "", "the fleet node_id being revoked (required)")
	fingerprint := fs.String("fingerprint", "", "the revoked certificate's fingerprint (required)")
	reason := fs.String("reason", "", "human-readable reason, recorded for audit")
	statusFlag := fs.String("status", revocation.StatusTainted, "tainted (soft) or revoked (hard)")
	keyPath := fs.String("key", "", "path to the operator's ed25519 private key (required)")
	out := fs.String("out", "", "output file for the signed envelope (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *nodeID == "" || *fingerprint == "" || *keyPath == "" {
		return fmt.Errorf("--node-id, --fingerprint, and --key are required")
	}

	signer, err := identity.NewEd25519SignerFromFile(*keyPath)
	if err != nil {
		return fmt.Errorf("loading operator key: %w", err)
	}

	now := time.Now()
	rec, err := revocation.Build(*nodeID, *fingerprint, *reason, *statusFlag, signer, now)
	if err != nil {
		return fmt.Errorf("building revocation record: %w", err)
	}
	payload, err := proto.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling revocation record: %w", err)
	}

	env, err := signOperatorEnvelope(crdt.OpRevocation, payload, signer, now)
	if err != nil {
		return err
	}
	envBytes, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(envBytes)

	if *out == "" {
		fmt.Println(encoded)
		return nil
	}
	if err := os.WriteFile(*out, []byte(encoded+"\n"), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", *out, err)
	}
	fmt.Printf("wrote signed revocation (op_id=%s) to %s\n", env.GetOpId(), *out)
	return nil
}

// cmdRevokeSubmit reads an envelope produced by `revoke sign` and submits it
// to a running node's admin API. It never touches an operator key.
func cmdRevokeSubmit(args []string) error {
	fs := flag.NewFlagSet("revoke submit", flag.ContinueOnError)
	file := fs.String("file", "", "signed envelope file from `revoke sign` (default: read stdin)")
	socket := fs.String("socket", "", "admin API Unix socket")
	cfgPath := fs.String("config", "", "daemon config file to read the socket path from")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var encoded []byte
	var err error
	if *file != "" {
		encoded, err = os.ReadFile(*file)
	} else {
		encoded, err = readAllStdin()
	}
	if err != nil {
		return fmt.Errorf("reading signed envelope: %w", err)
	}

	env, err := decodeEnvelope(encoded)
	if err != nil {
		return err
	}

	socketPath, err := resolveSocket(*socket, *cfgPath)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to admin socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := frienv1.NewAdminServiceClient(conn).InjectOperatorOp(ctx, &frienv1.InjectOperatorOpRequest{Envelope: env})
	if err != nil {
		return fmt.Errorf("InjectOperatorOp: %w", err)
	}
	fmt.Printf("accepted, op_id=%s\n", resp.GetOpId())
	return nil
}

// signOperatorEnvelope wraps payload in an OperationEnvelope signed by the
// operator key. node_id is deliberately not the target of the op (that lives
// inside the payload) -- it is set to a fresh random identifier so repeated
// operator ops can never collide on the (node_id, seq) equivocation index
// real nodes use for their own causal chains; operator control ops aren't
// part of any node's chain and carry no parents.
func signOperatorEnvelope(opType string, payload []byte, signer *identity.Ed25519Signer, now time.Time) (*frienv1.OperationEnvelope, error) {
	opID, err := randomID("op_")
	if err != nil {
		return nil, err
	}
	pseudoNode, err := randomID("operator_")
	if err != nil {
		return nil, err
	}
	var seqBuf [8]byte
	if _, err := rand.Read(seqBuf[:]); err != nil {
		return nil, fmt.Errorf("generating seq: %w", err)
	}

	sum := sha256.Sum256(payload)
	env := &frienv1.OperationEnvelope{
		ProtoVersion: 1,
		OpId:         opID,
		OpType:       opType,
		NodeId:       pseudoNode,
		Hlc:          crdt.Timestamp{Wall: now.UnixMilli(), NodeID: pseudoNode}.String(),
		Seq:          binary.BigEndian.Uint64(seqBuf[:]),
		PayloadHash:  "sha256:" + hex.EncodeToString(sum[:]),
		Payload:      payload,
		SignedBy:     "operator",
	}
	msg := identity.CanonicalSignedContent(env.GetProtoVersion(), env.GetOpId(), env.GetOpType(), env.GetNodeId(), env.GetHlc(), env.GetSeq(), env.GetParents(), env.GetPayloadHash(), env.GetSignedBy())
	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("signing envelope: %w", err)
	}
	env.KeyId = signer.PublicKeyID()
	env.Signature = sig
	return env, nil
}

func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating id: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func decodeEnvelope(encoded []byte) (*frienv1.OperationEnvelope, error) {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(raw, trimNewline(encoded))
	if err != nil {
		return nil, fmt.Errorf("decoding base64 envelope: %w", err)
	}
	var env frienv1.OperationEnvelope
	if err := proto.Unmarshal(raw[:n], &env); err != nil {
		return nil, fmt.Errorf("unmarshaling envelope: %w", err)
	}
	return &env, nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}
