package membership

import (
	"sync"
	"time"
)

// State is a peer's membership status in the SWIM failure detector.
type State uint8

const (
	StateAlive   State = iota // responding to probes
	StateSuspect              // missed a probe; awaiting refutation or timeout
	StateDead                 // suspicion timed out without refutation
	StateLeft                 // announced a graceful departure
)

func (s State) String() string {
	switch s {
	case StateAlive:
		return "alive"
	case StateSuspect:
		return "suspect"
	case StateDead:
		return "dead"
	case StateLeft:
		return "left"
	default:
		return "unknown"
	}
}

// Member is the local view of one peer.
type Member struct {
	NodeID      string
	Addresses   []string
	State       State
	Incarnation uint64
	StateChange time.Time
}

// Update is a membership claim about one node, exchanged via gossip. Conflicts
// between competing claims are resolved by (state, incarnation) per the SWIM
// rules: a higher incarnation always wins, and at equal incarnation a more
// "negative" state (suspect over alive, dead over suspect) wins.
type Update struct {
	NodeID      string
	Addresses   []string
	State       State
	Incarnation uint64
}

// ApplyResult reports what changed when an Update was merged.
type ApplyResult struct {
	Changed       bool     // local view moved to a new state/incarnation
	SelfRefute    bool     // the update accused this node; caller must broadcast alive
	Incarnation   uint64   // the refuting incarnation, when SelfRefute is set
	AddrConflict  bool     // an accepted alive claim moved a known node's address
	PrevAddresses []string // the address the node advertised before the conflict
}

// MemberList is the node's authoritative roster. All mutation goes through Apply
// and ExpireSuspects so the SWIM merge rules are enforced in one place.
type MemberList struct {
	mu       sync.Mutex
	localID  string
	localInc uint64
	members  map[string]*Member
	now      func() time.Time
}

func NewMemberList(localID string, now func() time.Time) *MemberList {
	if now == nil {
		now = time.Now
	}
	return &MemberList{
		localID: localID,
		members: make(map[string]*Member),
		now:     now,
	}
}

// LocalIncarnation returns the node's current incarnation number.
func (m *MemberList) LocalIncarnation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.localInc
}

// Apply merges one Update and returns what changed. An accusation against the
// local node never changes the roster; instead it raises the local incarnation
// and asks the caller to broadcast a fresh alive claim that out-ranks it.
func (m *MemberList) Apply(u Update) ApplyResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u.NodeID == m.localID {
		if u.State != StateAlive && u.Incarnation >= m.localInc {
			m.localInc = u.Incarnation + 1
			return ApplyResult{Changed: true, SelfRefute: true, Incarnation: m.localInc}
		}
		return ApplyResult{}
	}

	cur, ok := m.members[u.NodeID]
	if !ok {
		m.members[u.NodeID] = &Member{
			NodeID:      u.NodeID,
			Addresses:   u.Addresses,
			State:       u.State,
			Incarnation: u.Incarnation,
			StateChange: m.now(),
		}
		return ApplyResult{Changed: true}
	}

	switch u.State {
	case StateAlive:
		if u.Incarnation > cur.Incarnation {
			cur.State = StateAlive
			cur.Incarnation = u.Incarnation
			cur.StateChange = m.now()
			res := ApplyResult{Changed: true}
			if len(u.Addresses) > 0 {
				if len(cur.Addresses) > 0 && !sameAddrs(cur.Addresses, u.Addresses) {
					res.AddrConflict = true
					res.PrevAddresses = cur.Addresses
				}
				cur.Addresses = u.Addresses
			}
			return res
		}
	case StateSuspect:
		if u.Incarnation >= cur.Incarnation && cur.State == StateAlive {
			cur.State = StateSuspect
			cur.Incarnation = u.Incarnation
			cur.StateChange = m.now()
			return ApplyResult{Changed: true}
		}
	case StateDead, StateLeft:
		if u.Incarnation >= cur.Incarnation && cur.State != StateDead && cur.State != StateLeft {
			cur.State = u.State
			cur.Incarnation = u.Incarnation
			cur.StateChange = m.now()
			return ApplyResult{Changed: true}
		}
	}
	return ApplyResult{}
}

// ExpireSuspects promotes any suspect older than timeout to dead and returns the
// updates for the newly-dead members so the caller can disseminate them.
func (m *MemberList) ExpireSuspects(timeout time.Duration) []Update {
	m.mu.Lock()
	defer m.mu.Unlock()

	var dead []Update
	for _, mem := range m.members {
		if mem.State == StateSuspect && m.now().Sub(mem.StateChange) >= timeout {
			mem.State = StateDead
			mem.StateChange = m.now()
			dead = append(dead, Update{NodeID: mem.NodeID, State: StateDead, Incarnation: mem.Incarnation})
		}
	}
	return dead
}

// Members returns a copy of the full roster.
func (m *MemberList) Members() []Member {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Member, 0, len(m.members))
	for _, mem := range m.members {
		out = append(out, *mem)
	}
	return out
}

// ActiveMembers returns peers that are still probe-eligible (alive or suspect),
// which are the candidates for both probe targets and indirect-probe relays.
func (m *MemberList) ActiveMembers() []Member {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Member
	for _, mem := range m.members {
		if mem.State == StateAlive || mem.State == StateSuspect {
			out = append(out, *mem)
		}
	}
	return out
}

// sameAddrs compares two address sets regardless of order.
func sameAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		if seen[x] == 0 {
			return false
		}
		seen[x]--
	}
	return true
}

// Get returns the current view of one member.
func (m *MemberList) Get(nodeID string) (Member, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mem, ok := m.members[nodeID]; ok {
		return *mem, true
	}
	return Member{}, false
}
