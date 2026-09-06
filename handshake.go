package main

import (
	"bytes"
	"fmt"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/encoding"
	tmp2p "github.com/cometbft/cometbft/proto/tendermint/p2p"
)

// The peer handshake is a separate surface from consensus voting, and it is the
// one a post-quantum consensus key does not touch.
//
// CometBFT's SecretConnection runs a Station-to-Station exchange: each side
// sends a 32-byte ephemeral X25519 public key, both derive a shared secret with
// X25519 Diffie-Hellman, and then each side sends an AuthSigMessage carrying its
// node identity public key and a signature over the handshake transcript.
//
// Two properties come out of that, and they fail at different times:
//
//   - AUTHENTICATION, from the identity key and signature. Forging it is a live
//     attack: an adversary needs the quantum computer at the moment they
//     impersonate a peer.
//   - CONFIDENTIALITY, from the X25519 shared secret. Breaking it is a recorded
//     attack: an adversary captures the ciphertext today and decrypts it whenever
//     a cryptographically relevant quantum computer exists. Harvest now, decrypt
//     later.
//
// In upstream CometBFT v0.40.0 the shared secret comes from X25519 alone
// (p2p/conn/secret_connection.go, computeDHSecret -> curve25519.X25519), and the
// node identity key is generated as Ed25519 with no configuration hook
// (p2p/key.go, LoadOrGenNodeKey -> ed25519.GenPrivKey). Enabling ML-DSA-65
// consensus keys changes neither.

// KEM sizes are the published FIPS 203 parameters for ML-KEM-768, the level-3
// parameter set X-Wing builds on. They are constants from the standard, not
// measurements taken by this tool.
const (
	mlkem768EncapsulationKeyBytes = 1184
	mlkem768CiphertextBytes       = 1088
	x25519PublicKeyBytes          = 32
)

// HandshakeLeg is one direction of one handshake step.
type HandshakeLeg struct {
	Step     string
	Bytes    int
	Measured bool // true when this tool marshaled it; false when it is a published constant
	Note     string
}

// HandshakeProfile is a complete peer handshake, one side's outbound bytes.
//
// The two safety fields are separate because the properties fail on different
// clocks, and a single "quantum resistant" boolean cannot express that. An
// ML-DSA node key with an X25519 key agreement is safe against a future
// impersonator and not safe against an adversary recording packets today; the
// reverse combination is not offered by anything here but would be equally
// lopsided. Collapsing the two into one flag is how the earlier version of this
// tool ended up asserting that a post-quantum identity key "buys nothing".
type HandshakeProfile struct {
	Name         string
	Legs         []HandshakeLeg
	KeyAgreement string

	// SafeAgainstRecordedTraffic is confidentiality: does the session key
	// survive an adversary who captured the traffic today and gets a quantum
	// computer later? This is the harvest-now-decrypt-later property, and it
	// comes from the KEY AGREEMENT alone.
	SafeAgainstRecordedTraffic bool

	// SafeAgainstForgedIdentity is authentication: once a quantum computer can
	// forge Ed25519, can an attacker impersonate a peer? This comes from the
	// NODE IDENTITY KEY alone, and it is a live attack rather than a
	// retroactive one.
	SafeAgainstForgedIdentity bool
}

func (h HandshakeProfile) Total() int {
	n := 0
	for _, l := range h.Legs {
		n += l.Bytes
	}
	return n
}

// authSigMessageBytes marshals a real CometBFT AuthSigMessage carrying an
// identity key of the given scheme, using CometBFT's own generated protobuf
// code. Ed25519 is marshaled from a real generated key; other schemes are
// measured by substituting a key and signature of the scheme's published length,
// which is what determines the wire size.
func authSigMessageBytes(scheme Scheme) (int, error) {
	if scheme.Name == "ed25519" {
		pk := ed25519.GenPrivKey().PubKey()
		pbKey, err := encoding.PubKeyToProto(pk)
		if err != nil {
			return 0, fmt.Errorf("encode ed25519 pubkey: %w", err)
		}
		msg := &tmp2p.AuthSigMessage{
			PubKey: pbKey,
			Sig:    bytes.Repeat([]byte{0xA5}, scheme.SigBytes),
		}
		b, err := msg.Marshal()
		if err != nil {
			return 0, fmt.Errorf("marshal AuthSigMessage: %w", err)
		}
		return len(b), nil
	}

	// For a scheme CometBFT has no key type for, the wire cost is still
	// determined by the two lengths. Measure the Ed25519 message and adjust by
	// the difference in key and signature length; the protobuf field tags and
	// length prefixes are accounted for by re-marshaling with padded byte runs.
	base := ed25519.GenPrivKey().PubKey()
	pbKey, err := encoding.PubKeyToProto(base)
	if err != nil {
		return 0, fmt.Errorf("encode base pubkey: %w", err)
	}
	msg := &tmp2p.AuthSigMessage{
		PubKey: pbKey,
		Sig:    bytes.Repeat([]byte{0xA5}, scheme.SigBytes),
	}
	b, err := msg.Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshal AuthSigMessage: %w", err)
	}
	// Swap the 32-byte Ed25519 key for one of the scheme's key length. The
	// difference is the key bytes plus any growth in the length prefix.
	delta := scheme.PubKeyBytes - ed25519.PubKeySize
	extraPrefix := varintGrowth(ed25519.PubKeySize, scheme.PubKeyBytes)
	return len(b) + delta + extraPrefix, nil
}

// varintGrowth reports how many extra bytes a protobuf length prefix needs when
// a field grows from one length to another.
func varintGrowth(from, to int) int {
	return varintLen(to) - varintLen(from)
}

func varintLen(n int) int {
	l := 1
	for n >= 128 {
		n >>= 7
		l++
	}
	return l
}

// UpstreamHandshake is what CometBFT v0.40.0 actually sends today.
func UpstreamHandshake() (HandshakeProfile, error) {
	auth, err := authSigMessageBytes(Scheme{Name: "ed25519", SigBytes: 64, PubKeyBytes: 32})
	if err != nil {
		return HandshakeProfile{}, err
	}
	return HandshakeProfile{
		Name: "upstream v0.40.0 (X25519 + Ed25519 node key)",
		Legs: []HandshakeLeg{
			{Step: "ephemeral X25519 public key", Bytes: x25519PublicKeyBytes, Measured: false,
				Note: "fixed 32-byte array in secret_connection.go"},
			{Step: "AuthSigMessage (node key + transcript signature)", Bytes: auth, Measured: true,
				Note: "marshaled with CometBFT's own protobuf code"},
		},
		KeyAgreement:               "X25519 Diffie-Hellman",
		SafeAgainstRecordedTraffic: false,
		SafeAgainstForgedIdentity:  false, // Ed25519 node key
	}, nil
}

// PQAuthOnlyHandshake is the shape a chain gets if it upgrades only the node
// identity key to a post-quantum scheme and leaves the key agreement alone.
//
// It is NOT useless, and an earlier version of this file implied it was. It
// buys authentication against a future forger. What it does not buy is
// confidentiality, because the session key is still derived from X25519 alone,
// so a capture taken today is decrypted later regardless.
//
// Upstream does not offer this today: the node key is hardcoded Ed25519.
func PQAuthOnlyHandshake(scheme Scheme) (HandshakeProfile, error) {
	auth, err := authSigMessageBytes(scheme)
	if err != nil {
		return HandshakeProfile{}, err
	}
	return HandshakeProfile{
		Name: fmt.Sprintf("PQ node identity only (X25519 + %s node key)", scheme.Name),
		Legs: []HandshakeLeg{
			{Step: "ephemeral X25519 public key", Bytes: x25519PublicKeyBytes, Measured: false,
				Note: "unchanged: the shared secret still comes from X25519 alone"},
			{Step: "AuthSigMessage (node key + transcript signature)", Bytes: auth, Measured: true,
				Note: "grows with the identity scheme"},
		},
		KeyAgreement:               "X25519 Diffie-Hellman",
		SafeAgainstRecordedTraffic: false, // the session key is still X25519 alone
		SafeAgainstForgedIdentity:  true,  // this is what the extra ~5 KB buys
	}, nil
}

// HybridKEMHandshake is the shape that actually closes the recorded-traffic
// exposure: a hybrid key agreement carrying both an X25519 share and an ML-KEM
// encapsulation, so the session key survives unless BOTH are broken.
func HybridKEMHandshake(scheme Scheme) (HandshakeProfile, error) {
	auth, err := authSigMessageBytes(scheme)
	if err != nil {
		return HandshakeProfile{}, err
	}
	return HandshakeProfile{
		Name: fmt.Sprintf("hybrid KEM (X25519 + ML-KEM-768, %s node key)", scheme.Name),
		Legs: []HandshakeLeg{
			{Step: "ephemeral X25519 public key", Bytes: x25519PublicKeyBytes, Measured: false,
				Note: "retained, so the exchange is no weaker than today"},
			{Step: "ML-KEM-768 encapsulation key", Bytes: mlkem768EncapsulationKeyBytes, Measured: false,
				Note: "FIPS 203 published parameter"},
			{Step: "ML-KEM-768 ciphertext", Bytes: mlkem768CiphertextBytes, Measured: false,
				Note: "FIPS 203 published parameter"},
			{Step: "AuthSigMessage (node key + transcript signature)", Bytes: auth, Measured: true,
				Note: "grows with the identity scheme"},
		},
		KeyAgreement:               "X25519 + ML-KEM-768, both required",
		SafeAgainstRecordedTraffic: true,
		SafeAgainstForgedIdentity:  true,
	}, nil
}
