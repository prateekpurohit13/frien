package version

import "errors"

// ErrNoCommonVersion is returned when two peers share no supported protocol
// version. Per PROTOCOL.md a session with no common version is rejected.
var ErrNoCommonVersion = errors.New("version: no mutually-supported protocol version")

// HighestCommon returns the highest protocol version supported by both this node
// and the remote peer, or 0 if there is no overlap. The result is independent of
// the order in which the peer advertises its versions.
func HighestCommon(remote []uint32) uint32 {
	var best uint32
	for _, rv := range remote {
		if IsSupported(rv) && rv > best {
			best = rv
		}
	}
	return best
}

// Resolve is the responder side of negotiation: given the initiator's advertised
// versions it picks the session version or rejects the handshake.
func Resolve(remote []uint32) (uint32, error) {
	if v := HighestCommon(remote); v != 0 {
		return v, nil
	}
	return 0, ErrNoCommonVersion
}

// Accept is the initiator side: it validates the version the responder selected.
// A responder must never be able to push this node onto a version it does not
// itself support, so an unsupported or zero selection is rejected.
func Accept(negotiated uint32) (uint32, error) {
	if negotiated != 0 && IsSupported(negotiated) {
		return negotiated, nil
	}
	return 0, ErrNoCommonVersion
}
