---- MODULE frien ----
(* Skeleton spec for the frien mesh: membership FSM, partition-safe quorum
   before enforcement, misbehavior quarantine, and mesh-wide revocation.
   Not yet model-checked end-to-end; fleshes out module structure and the
   core safety properties so Phase 4/5 implementation can be checked against
   it incrementally. *)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Node,           \* set of node identifiers in the mesh
    Quorum,         \* set of subsets of Node that constitute a valid quorum
    NULL

ASSUME Quorum \subseteq SUBSET Node

VARIABLES
    membership,     \* [Node -> {"alive", "suspect", "dead", "left"}]
    revoked,        \* subset of Node whose certs have been revoked
    quarantined,    \* subset of Node quarantined after a misbehavior proof
    misbehaved,     \* subset of Node with an outstanding misbehavior proof
    enforced        \* set of enforcement decisions applied, each a
                    \* record [approvers: subset Node, target: Node]

vars == <<membership, revoked, quarantined, misbehaved, enforced>>

TypeOK ==
    /\ membership \in [Node -> {"alive", "suspect", "dead", "left"}]
    /\ revoked \subseteq Node
    /\ quarantined \subseteq Node
    /\ misbehaved \subseteq Node
    /\ enforced \subseteq [approvers: SUBSET Node, target: Node]

Init ==
    /\ membership = [n \in Node |-> "alive"]
    /\ revoked = {}
    /\ quarantined = {}
    /\ misbehaved = {}
    /\ enforced = {}

\* ─── Membership FSM ────────────────────────────────────────────────────────

Suspect(n) ==
    /\ membership[n] = "alive"
    /\ membership' = [membership EXCEPT ![n] = "suspect"]
    /\ UNCHANGED <<revoked, quarantined, misbehaved, enforced>>

Recover(n) ==
    /\ membership[n] = "suspect"
    /\ membership' = [membership EXCEPT ![n] = "alive"]
    /\ UNCHANGED <<revoked, quarantined, misbehaved, enforced>>

Declare_Dead(n) ==
    /\ membership[n] = "suspect"
    /\ membership' = [membership EXCEPT ![n] = "dead"]
    /\ UNCHANGED <<revoked, quarantined, misbehaved, enforced>>

Leave(n) ==
    /\ membership[n] \in {"alive", "suspect"}
    /\ membership' = [membership EXCEPT ![n] = "left"]
    /\ UNCHANGED <<revoked, quarantined, misbehaved, enforced>>

\* ─── Misbehavior, quarantine, and revocation ───────────────────────────────

\* A node that equivocates (produces conflicting DAG entries for the same
\* sequence number) is flagged; quarantine is automatic and local, revocation
\* requires an operator-signed action out-of-band.
DetectMisbehavior(n) ==
    /\ n \notin misbehaved
    /\ misbehaved' = misbehaved \union {n}
    /\ quarantined' = quarantined \union {n}
    /\ UNCHANGED <<membership, revoked, enforced>>

Revoke(n) ==
    /\ n \notin revoked
    /\ revoked' = revoked \union {n}
    /\ UNCHANGED <<membership, quarantined, misbehaved, enforced>>

\* ─── Enforcement ────────────────────────────────────────────────────────────

\* Enforcement may only be applied if the approving set of nodes forms a
\* valid quorum, none of the approvers are revoked or quarantined, and the
\* target itself is not the sole source of the decision (no self-approval).
CanEnforce(approvers, target) ==
    /\ approvers \in Quorum
    /\ approvers \cap revoked = {}
    /\ approvers \cap quarantined = {}
    /\ target \notin approvers

Enforce(approvers, target) ==
    /\ CanEnforce(approvers, target)
    /\ enforced' = enforced \union {[approvers |-> approvers, target |-> target]}
    /\ UNCHANGED <<membership, revoked, quarantined, misbehaved>>

Next ==
    \/ \E n \in Node : Suspect(n) \/ Recover(n) \/ Declare_Dead(n) \/ Leave(n)
    \/ \E n \in Node : DetectMisbehavior(n)
    \/ \E n \in Node : Revoke(n)
    \/ \E approvers \in Quorum, target \in Node : Enforce(approvers, target)

Spec == Init /\ [][Next]_vars

\* ─── Safety properties ──────────────────────────────────────────────────────

\* No enforcement decision was ever approved by a coalition smaller than a
\* quorum, nor by a set containing a revoked or quarantined node.
NoSubQuorumEnforcement ==
    \A e \in enforced :
        /\ e.approvers \in Quorum
        /\ e.approvers \cap revoked = {}
        /\ e.approvers \cap quarantined = {}

\* A revoked node can never subsequently be part of an approving quorum.
RevokedNeverApproves ==
    \A e \in enforced : e.approvers \cap revoked = {}

\* Once quarantined, a node stays quarantined until an explicit (unmodeled
\* here) operator clearance action -- this skeleton has no such action yet,
\* so quarantine is monotonically non-decreasing.
QuarantineMonotonic ==
    [][quarantined \subseteq quarantined']_vars

THEOREM Spec => [](TypeOK /\ NoSubQuorumEnforcement /\ RevokedNeverApproves)

====
