//! In-memory stop of one Instance, shared by the Manager facade and the Instance's actor.
//!
//! A user Stop / emergency stop sets it synchronously, before the stop command is queued to the
//! actor and before the latch reaches the disk. While it is set the actor neither opens the
//! payload gate nor starts a generation, so a command still waiting in the mailbox, a slow or
//! failing latch write, or a reconcile that reads the old "running" intent cannot bring the
//! Instance back. Only a durable Start requested after the stop lifts it.
//!
//! The hold dies with the manager process; a stop that is not durable is mirrored on disk by its
//! marker ([`crate::stops`]). A manager start that finds such evidence holds the Instance again
//! as an *unconfirmed* stop: nothing retries its latch, and the Instance stays closed in
//! `recovery_required` until the user stops it, starts it or clears its emergency.

use vpn_sync::Mutex;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about one stop (in force, emergency, on disk, unconfirmed), each read on its own"
)]
pub struct HoldState {
    /// Bumped by every stop request; a Start lifts only the stops it has seen.
    pub epoch: u64,
    /// A user stop is in force.
    pub stopped: bool,
    /// ...and it was (or included) an emergency stop, until the emergency is cleared.
    pub emergency: bool,
    /// Epoch of the latest emergency stop.
    pub emergency_epoch: u64,
    /// The stop is on disk (its latch, or a later intent write that also says stopped).
    pub durable: bool,
    /// The stop was asked for before this manager started and could not be confirmed on disk:
    /// the user has to decide (Stop, emergency stop, Start or clearing the emergency).
    pub unconfirmed: bool,
}

impl HoldState {
    /// A stop is in force that is not on disk: what its marker file stands for.
    pub const fn pending(&self) -> bool {
        self.stopped && !self.durable
    }
}

#[derive(Default)]
pub struct Hold {
    state: Mutex<HoldState>,
    /// Serialises the Instance's durable intent writes in request order: a stop latch never
    /// commits before an earlier Start, and a latch retry never overwrites a later Start.
    pub writes: tokio::sync::Mutex<()>,
}

impl Hold {
    /// The hold of an Instance whose stop (an emergency stop with `emergency`) was asked for
    /// before this manager started and is not on disk.
    pub fn unconfirmed(emergency: bool) -> Self {
        Self {
            state: Mutex::new(HoldState {
                epoch: 1,
                stopped: true,
                emergency,
                emergency_epoch: u64::from(emergency),
                durable: false,
                unconfirmed: true,
            }),
            writes: tokio::sync::Mutex::new(()),
        }
    }

    pub fn get(&self) -> HoldState {
        *self.state.lock()
    }

    pub fn stopped(&self) -> bool {
        self.state.lock().stopped
    }

    /// A stop was requested: hold from now on. Returns the stop's epoch. The user acted in this
    /// run, so a stop carried over from before is now theirs (no longer unconfirmed).
    pub fn stop(&self, emergency: bool) -> u64 {
        let mut s = self.state.lock();
        s.epoch += 1;
        s.stopped = true;
        if emergency {
            s.emergency = true;
            s.emergency_epoch = s.epoch;
        }
        s.durable = false;
        s.unconfirmed = false;
        s.epoch
    }

    /// The latch of stop `epoch` is on disk.
    pub fn latched(&self, epoch: u64) {
        let mut s = self.state.lock();
        if s.epoch == epoch && s.stopped {
            s.durable = true;
        }
    }

    /// A Start requested at epoch `seen` is on disk: it lifts the hold unless a stop arrived
    /// after it was requested.
    pub fn started(&self, seen: u64) {
        let mut s = self.state.lock();
        if s.epoch == seen {
            *s = HoldState {
                epoch: s.epoch,
                ..HoldState::default()
            };
        }
    }

    /// Clearing the emergency latch, requested at epoch `seen`, is on disk: it clears the
    /// emergencies it has seen, and the Instance is durably stopped unless a stop came after.
    pub fn emergency_cleared(&self, seen: u64) {
        let mut s = self.state.lock();
        if s.emergency_epoch <= seen {
            s.emergency = false;
        }
        if s.epoch == seen && s.stopped {
            s.durable = true;
            s.unconfirmed = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_writes_that_saw_a_stop_lift_or_clear_it() {
        let hold = Hold::default();
        let seen = hold.get().epoch;
        let emergency = hold.stop(true);
        // A Start requested before this stop committed after it: the stop stays.
        hold.started(seen);
        assert!(hold.stopped());
        hold.latched(emergency);
        assert!(hold.get().durable);

        // A clear requested after the emergency, overtaken by a plain stop: the emergency is
        // cleared, but the newer stop is not on disk until its own latch is.
        let cleared_at = hold.get().epoch;
        let stop = hold.stop(false);
        hold.emergency_cleared(cleared_at);
        hold.latched(emergency);
        assert_eq!(
            hold.get(),
            HoldState {
                epoch: stop,
                stopped: true,
                emergency: false,
                emergency_epoch: emergency,
                durable: false,
                unconfirmed: false,
            }
        );
        hold.latched(stop);
        assert!(hold.get().durable);

        // An emergency newer than the clear survives it.
        let seen = hold.get().epoch;
        hold.stop(true);
        hold.emergency_cleared(seen);
        assert!(hold.get().emergency);

        let seen = hold.get().epoch;
        hold.started(seen);
        assert!(!hold.stopped() && !hold.get().emergency);
    }

    #[test]
    fn an_unconfirmed_stop_ends_only_with_the_users_decision() {
        // Stop again: the stop is the user's, pending until its latch is on disk.
        let hold = Hold::unconfirmed(false);
        assert!(hold.get().pending() && hold.get().unconfirmed);
        let epoch = hold.stop(false);
        assert!(hold.get().pending() && !hold.get().unconfirmed);
        hold.latched(epoch);
        assert!(!hold.get().pending());

        // Start: lifted once the Start is on disk.
        let hold = Hold::unconfirmed(false);
        hold.started(hold.get().epoch);
        assert!(!hold.get().unconfirmed && !hold.stopped());

        // An emergency stays an emergency: clearing it leaves the Instance durably stopped.
        let hold = Hold::unconfirmed(true);
        let s = hold.get();
        assert!(s.emergency && s.unconfirmed && s.pending());
        hold.emergency_cleared(s.epoch);
        let s = hold.get();
        assert!(s.stopped && s.durable && !s.emergency && !s.unconfirmed);
    }
}
