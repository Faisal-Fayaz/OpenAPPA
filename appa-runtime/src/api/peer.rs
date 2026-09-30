//! Peer messages: one protected session's `SendMessage` to another.
//!
//! A family records where it receives peer messages (`Addressed`). A send is released only
//! to the address of another live protected family, and the release records what was sent
//! (`PeerSent`) in the sender's log. The recipient's prompt hook matches the frame it was
//! delivered against that record, takes it once (`PeerTaken`), and admits the message at
//! the label the sender dispatched it under. A frame nothing matches is admitted
//! unattributed.

use appa_engine::fact::{Fact, TrajectoryOpening};
use appa_engine::transition::PeerOrigin;
use appa_engine::value::{DispatchId, PeerMessageId, RawResultDigest};
use appa_eventlog::{HostObservation, Log, PeerLedger};
use appa_runtime_api::{PeerAddress, PeerDigest, PeerFrame, ProposedCall, SessionTitle, TrajectoryId};

use super::{EventError, Runtime};
use crate::engine::EngineRefusal;

/// The host tool one session messages another with.
pub(crate) const SEND_MESSAGE: &str = "host/claude-code/SendMessage";

/// The key prefix an `Addressed` record is found under.
const ADDRESS_KEY: &str = "peer-address:";

/// How many protected sessions a refused send lists.
const LISTED_PEERS: usize = 20;

/// Where a `SendMessage` call may go.
pub(crate) enum PeerSend {
    /// Another live protected family, and the digest of the message it will receive.
    Resolved {
        recipient: TrajectoryId,
        digest: PeerDigest,
    },
    /// No protected family receives at `to`: the feedback that says so.
    Refused { feedback: String },
}

/// One peer message, matched: what the receiving trajectory admits.
pub(crate) struct PeerMatch {
    pub(crate) id: PeerMessageId,
    pub(crate) digest: RawResultDigest,
    pub(crate) origin: PeerOrigin,
}

fn address_key(address: &PeerAddress) -> String {
    format!("{ADDRESS_KEY}{address}")
}

fn opening(log: &Log) -> Option<&TrajectoryOpening> {
    match log.facts().first() {
        Some(Fact::TrajectoryOpened(opening)) => Some(opening),
        _ => None,
    }
}

fn fresh_id() -> PeerMessageId {
    PeerMessageId::new(uuid::Uuid::new_v4().to_string()).expect("a uuid is never empty")
}

fn raw_digest(digest: &PeerDigest) -> RawResultDigest {
    RawResultDigest::from_hex(&digest.to_string()).expect("a peer digest renders as 64 hex digits")
}

fn unattributed(digest: &PeerDigest) -> PeerMatch {
    PeerMatch {
        id: fresh_id(),
        digest: raw_digest(digest),
        origin: PeerOrigin::Unattributed,
    }
}

impl Runtime {
    /// This family receives peer messages at `address`. Recorded only when it is not already
    /// the family's address, so a resumed session leaves one record.
    pub(crate) fn record_address(&self, root: &TrajectoryId, address: &PeerAddress) -> Result<(), EventError> {
        self.inner.append_host_with(root, |log| {
            let ledger = PeerLedger::fold(log.host_records());
            let observation = (ledger.address != Some(address)).then(|| HostObservation::Addressed {
                address: address.clone(),
                title: ledger.title.cloned(),
            });
            Ok((observation, ()))
        })
    }

    /// The title the host shows for an addressed family, for a refused send to list it by.
    pub(crate) fn record_title(&self, root: &TrajectoryId, title: &SessionTitle) -> Result<(), EventError> {
        self.inner.append_host_with(root, |log| {
            let ledger = PeerLedger::fold(log.host_records());
            let observation = match ledger.address {
                Some(address) if ledger.title != Some(title) => Some(HostObservation::Addressed {
                    address: address.clone(),
                    title: Some(title.clone()),
                }),
                _ => None,
            };
            Ok((observation, ()))
        })
    }

    /// The one family whose latest address is `address`. A family that moved to another
    /// address no longer answers for this one, and two families claiming it answer for
    /// nobody.
    fn addressed_root(&self, address: &PeerAddress) -> Result<Option<TrajectoryId>, EventError> {
        let candidates = self
            .inner
            .store
            .roots_mentioning(&address_key(address))
            .map_err(|error| {
                self.inner
                    .note_store_error(None, crate::events::StoreOperation::Read, &error);
                EventError::Storage(error.to_string())
            })?;
        let mut current = Vec::new();
        for root in candidates {
            let log = self.inner.log(&root)?;
            if PeerLedger::fold(log.host_records()).address == Some(address) {
                current.push(root);
            }
        }
        Ok(match <[TrajectoryId; 1]>::try_from(current) {
            Ok([root]) => Some(root),
            Err(_) => None,
        })
    }

    /// Where this family's `SendMessage` call goes: another live protected family named by
    /// its address, or nowhere.
    pub(crate) fn peer_send(&self, sender: &TrajectoryId, call: &ProposedCall) -> Result<PeerSend, EventError> {
        let arguments = serde_json::from_str::<serde_json::Value>(call.arguments.get()).unwrap_or_default();
        let to = arguments.get("to").and_then(serde_json::Value::as_str);
        let message = arguments.get("message").and_then(serde_json::Value::as_str);
        let recipient = match to.map(PeerAddress::parse) {
            Some(Ok(address)) => self.addressed_root(&address)?,
            _ => None,
        };
        match (recipient, message) {
            (Some(recipient), Some(message)) if recipient != *sender => {
                tracing::debug!(sender = %sender.0, recipient = %recipient.0, "a peer message resolved its recipient");
                Ok(PeerSend::Resolved {
                    recipient,
                    digest: PeerDigest::of_body(message),
                })
            }
            _ => {
                tracing::debug!(sender = %sender.0, "a peer message names no other protected session");
                Ok(PeerSend::Refused {
                    feedback: self.peer_listing(sender)?,
                })
            }
        }
    }

    /// The refusal of a send that reaches no protected session, with the sessions it can
    /// reach.
    fn peer_listing(&self, sender: &TrajectoryId) -> Result<String, EventError> {
        let roots = self.inner.store.roots_mentioning_prefix(ADDRESS_KEY).map_err(|error| {
            self.inner
                .note_store_error(None, crate::events::StoreOperation::Read, &error);
            EventError::Storage(error.to_string())
        })?;
        let mut peers = Vec::new();
        for root in roots.iter().filter(|root| *root != sender) {
            let log = self.inner.log(root)?;
            let ledger = PeerLedger::fold(log.host_records());
            if let Some(address) = ledger.address {
                let title = ledger.title.map_or("(untitled)", SessionTitle::as_str);
                peers.push(format!("  {title} → {address}"));
            }
        }
        let rule = "SendMessage reaches only another protected session, named by its address: set `to` to one \
                    address below.";
        let listed = match peers.len() {
            0 => "No other protected session has an address.".to_string(),
            count if count > LISTED_PEERS => format!(
                "{}\n  … and {} more",
                peers[..LISTED_PEERS].join("\n"),
                count - LISTED_PEERS
            ),
            _ => peers.join("\n"),
        };
        Ok(format!("{rule}\n{listed}"))
    }

    /// Record a released send in the sender family's log, where the recipient's prompt hook
    /// will look for it.
    pub(crate) fn record_peer_sent(
        &self,
        sender: &TrajectoryId,
        recipient: TrajectoryId,
        digest: PeerDigest,
        dispatch: DispatchId,
    ) -> Result<(), EventError> {
        let sent = HostObservation::PeerSent {
            id: fresh_id().as_str().to_string(),
            recipient,
            digest,
            dispatch,
        };
        self.inner.append_host_with(sender, |_| Ok((Some(sent.clone()), ())))
    }

    /// What one delivered frame admits into `receiver`: the sender's record, taken once, or
    /// nothing a sender stands behind.
    pub(crate) fn peer_match(
        &self,
        receiver: &TrajectoryId,
        frame: &PeerFrame,
        text: &str,
    ) -> Result<PeerMatch, EventError> {
        let (from, digest) = match frame {
            PeerFrame::Parsed { from, digest } => (from, digest),
            PeerFrame::Malformed => {
                tracing::debug!(receiver = %receiver.0, "a malformed peer frame is admitted unattributed");
                return Ok(unattributed(&PeerDigest::of_body(text)));
            }
        };
        let sender = match self.addressed_root(from)? {
            Some(sender) if sender != *receiver && self.pinned_alike(&sender, receiver)? => sender,
            _ => {
                tracing::debug!(receiver = %receiver.0, "no protected session under this policy sent the peer frame");
                return Ok(unattributed(digest));
            }
        };
        let Some((id, dispatch)) = self.take_peer(&sender, receiver, digest)? else {
            tracing::debug!(receiver = %receiver.0, sender = %sender.0, "no pending send matches the peer frame");
            return Ok(unattributed(digest));
        };
        let label = self.dispatched_label(&sender, &dispatch)?;
        tracing::debug!(receiver = %receiver.0, sender = %sender.0, "the peer frame is attributed to its send");
        Ok(PeerMatch {
            id: PeerMessageId::new(id).map_err(|error| EventError::UntrustedLog(error.to_string()))?,
            digest: raw_digest(digest),
            origin: PeerOrigin::Attributed {
                sender: dispatch,
                label,
            },
        })
    }

    /// Two families opened under one policy for one principal: a label one records means the
    /// same to the other.
    fn pinned_alike(&self, sender: &TrajectoryId, receiver: &TrajectoryId) -> Result<bool, EventError> {
        let (sent, received) = (self.inner.log(sender)?, self.inner.log(receiver)?);
        Ok(match (opening(&sent), opening(&received)) {
            (Some(sent), Some(received)) => {
                sent.policy_digest == received.policy_digest && sent.principal == received.principal
            }
            _ => false,
        })
    }

    /// Take the oldest send from `sender` still pending for `receiver` with this digest. A
    /// racer that took it first leaves the next one, re-derived where the take lands.
    fn take_peer(
        &self,
        sender: &TrajectoryId,
        receiver: &TrajectoryId,
        digest: &PeerDigest,
    ) -> Result<Option<(String, DispatchId)>, EventError> {
        self.inner.append_host_with(sender, |log| {
            let ledger = PeerLedger::fold(log.host_records());
            Ok(
                match ledger
                    .pending
                    .iter()
                    .find(|pending| pending.recipient == receiver && pending.digest == digest)
                {
                    Some(pending) => (
                        Some(HostObservation::PeerTaken {
                            id: pending.id.to_string(),
                        }),
                        Some((pending.id.to_string(), pending.dispatch.clone())),
                    ),
                    None => (None, None),
                },
            )
        })
    }

    /// The label the sender's trajectory stood at when it dispatched the send.
    fn dispatched_label(
        &self,
        sender: &TrajectoryId,
        dispatch: &DispatchId,
    ) -> Result<appa_engine::label::Label, EventError> {
        let log = self.inner.log(sender)?;
        let deployment = self.inner.deployment();
        let policy = self.inner.resolve_policy(&deployment, &log)?;
        let view = policy.engine().rebuild_view(&log).map_err(EventError::from)?;
        view.views(dispatch.trajectory())
            .and_then(|views| views.receiving_bound(dispatch).cloned())
            .ok_or_else(|| {
                EngineRefusal::Invariant {
                    detail: "a pending peer message names a dispatch its sender's log never opened".to_string(),
                }
                .into()
            })
    }
}
