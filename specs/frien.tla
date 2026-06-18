-------------------------------- MODULE frien --------------------------------
(***************************************************************************)
(* TLA+ specification skeleton for frien's safety-critical protocols:      *)
(* membership, partition-safe quorum, quarantine, and revocation.          *)
(*                                                                         *)
(* This is the Phase 0 skeleton (docs/FRIEN_ARCHITECTURE.md §16). It models *)
(* the state and the safety INVARIANTS the design must preserve. The action *)
(* relation is intentionally abstract; later phases refine Next as each     *)
(* protocol is implemented, but the invariants below are the contract.     *)
(*                                                                         *)
(* The headline property is QuorumSafety: a node in a minority partition    *)
(* must never take fleet-scoped enforcement. frien favors consistency of    *)
(* the enforcement decision over availability of enforcement (an explicit   *)
(* CAP choice, docs §8.1).                                                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,           \* set of node identities (distinct CA-issued certs)
    SelfPlanes,      \* protected targets that must never be enforced against
    RequiredWeight,  \* quorum weight required for fleet-scoped enforcement
    Weight           \* [Nodes -> Nat]: trust-tier weight per node

ASSUME
    /\ RequiredWeight \in Nat
    /\ Weight \in [Nodes -> Nat]

VARIABLES
    memberState,   \* [Nodes -> {"alive","suspect","dead","left"}]
    revoked,       \* subset of Nodes: operator-signed revocations (monotonic)
    quarantined,   \* subset of Nodes: behavioral, immediate, local
    partition,     \* subset of Nodes the acting node can currently observe
    enforced       \* subset of targets currently under fleet-scoped enforcement

vars == <<memberState, revoked, quarantined, partition, enforced>>

MemberStates == {"alive", "suspect", "dead", "left"}

----------------------------------------------------------------------------
(* A node may contribute to quorum only if it is a distinct identity that is *)
(* alive, not revoked, not quarantined, and observable in the partition.     *)
EligibleVoters ==
    { n \in partition :
        /\ memberState[n] = "alive"
        /\ n \notin revoked
        /\ n \notin quarantined }

ObservedWeight == \* sum of weights of eligible voters
    LET Sum[S \in SUBSET Nodes] ==
            IF S = {} THEN 0
            ELSE LET x == CHOOSE e \in S : TRUE
                 IN Weight[x] + Sum[S \ {x}]
    IN Sum[EligibleVoters]

QuorumMet == ObservedWeight >= RequiredWeight

----------------------------------------------------------------------------
Init ==
    /\ memberState = [n \in Nodes |-> "alive"]
    /\ revoked = {}
    /\ quarantined = {}
    /\ partition = Nodes
    /\ enforced = {}

(* --- Abstract actions (refined per phase) --- *)

\* The network partitions: the acting node now observes only a subset P.
Partition(P) ==
    /\ P \subseteq Nodes
    /\ partition' = P
    /\ UNCHANGED <<memberState, revoked, quarantined, enforced>>

\* Operator-signed revocation. Monotonic: a revoked identity is never un-revoked.
Revoke(n) ==
    /\ n \in Nodes
    /\ revoked' = revoked \cup {n}
    /\ UNCHANGED <<memberState, quarantined, partition, enforced>>

\* Behavioral quarantine on equivocation detection (immediate, local).
Quarantine(n) ==
    /\ n \in Nodes
    /\ quarantined' = quarantined \cup {n}
    /\ UNCHANGED <<memberState, revoked, partition, enforced>>

\* Fleet-scoped enforcement is permitted only when quorum is met AND the target
\* is not a protected self-plane. This is the guarded transition the invariants
\* below constrain.
Enforce(target) ==
    /\ QuorumMet
    /\ target \notin SelfPlanes
    /\ enforced' = enforced \cup {target}
    /\ UNCHANGED <<memberState, revoked, quarantined, partition>>

Next ==
    \/ \E P \in SUBSET Nodes : Partition(P)
    \/ \E n \in Nodes : Revoke(n)
    \/ \E n \in Nodes : Quarantine(n)
    \/ \E t \in (SelfPlanes \cup Nodes) : Enforce(t)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(*                              SAFETY INVARIANTS                            *)
----------------------------------------------------------------------------

TypeOK ==
    /\ memberState \in [Nodes -> MemberStates]
    /\ revoked \subseteq Nodes
    /\ quarantined \subseteq Nodes
    /\ partition \subseteq Nodes
    /\ enforced \subseteq (SelfPlanes \cup Nodes)

\* QuorumSafety: nothing is ever enforced unless quorum was met. Equivalently, a
\* minority partition (insufficient observed weight) cannot enforce.
QuorumSafety == (enforced # {}) => QuorumMet

\* NoSelfLockout: frien's own planes are never enforced against.
NoSelfLockout == \A t \in SelfPlanes : t \notin enforced

\* QuarantineExcludesQuorum: a quarantined node never counts as an eligible voter.
QuarantineExcludesQuorum == \A n \in quarantined : n \notin EligibleVoters

\* RevocationExcludesQuorum: a revoked identity never counts toward quorum.
RevocationExcludesQuorum == \A n \in revoked : n \notin EligibleVoters

Safety ==
    /\ TypeOK
    /\ QuorumSafety
    /\ NoSelfLockout
    /\ QuarantineExcludesQuorum
    /\ RevocationExcludesQuorum

(* Check with TLC using a small finite model, e.g.:                          *)
(*   Nodes = {n1, n2, n3}, SelfPlanes = {self}, RequiredWeight = 3,          *)
(*   Weight = (n1 :> 1 @@ n2 :> 1 @@ n3 :> 1)                                 *)
(* INVARIANT Safety                                                          *)
=============================================================================
