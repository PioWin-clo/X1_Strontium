use std::time::{SystemTime, UNIX_EPOCH};

/// Per-window submission buffer size — **must match** the on-chain
/// contract's `MAX_SUBMISSIONS`. Shrunk to 6 in the v0.4 hotfix to fit X1's
/// 10 240 B CPI realloc cap; if you change this, also change the const in
/// `programs/x1-strontium/src/lib.rs` or the window-slot model will pick
/// more operators per window than the contract can accept, wasting gas on
/// `SubmissionsFull` rejections.
pub const MAX_SUBMISSIONS: usize = 6;

/// Membership state for the rotation set. Built from `config.rotation_peers`
/// (for manual configuration) or from the daemon's auto-fetched list of
/// on-chain active operators (`RpcClient::fetch_active_operators`), with
/// the node's own oracle pubkey always included.
#[derive(Debug, Clone)]
pub struct RotationState {
    pub active_oracles: Vec<[u8; 32]>,
}

impl RotationState {
    pub fn from_peers(peers: &[String], my_pubkey: &[u8; 32]) -> Self {
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for peer in peers {
            if let Ok(decoded) = bs58::decode(peer.trim()).into_vec() {
                if decoded.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&decoded);
                    keys.push(k);
                }
            }
        }
        if !keys.iter().any(|k| k == my_pubkey) {
            keys.push(*my_pubkey);
        }
        keys.sort();
        Self {
            active_oracles: keys,
        }
    }

    /// Build from already-decoded pubkey list (used by the auto-fetch path
    /// where the RPC helper returns `Vec<[u8; 32]>` directly).
    pub fn from_peers_raw(peers: &[[u8; 32]], my_pubkey: &[u8; 32]) -> Self {
        let mut keys: Vec<[u8; 32]> = peers.to_vec();
        if !keys.iter().any(|k| k == my_pubkey) {
            keys.push(*my_pubkey);
        }
        keys.sort();
        Self {
            active_oracles: keys,
        }
    }

    pub fn my_index(&self, my_pubkey: &[u8; 32]) -> usize {
        self.active_oracles
            .iter()
            .position(|k| k == my_pubkey)
            .unwrap_or(0)
    }

    pub fn n_oracles(&self) -> usize {
        std::cmp::max(self.active_oracles.len(), 1)
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decide whether this node is electing itself for the current window.
/// Returns `(is_my_turn, window_id, secs_until_next_window)`.
///
/// Thin wrapper over [`rotation_my_turn_at`] — all the actual logic lives
/// there as a pure function so unit tests can pass an arbitrary `now`.
pub fn rotation_my_turn(my_index: usize, n_oracles: usize, interval_s: u64) -> (bool, u64, u64) {
    let now = unix_secs();
    rotation_my_turn_at(my_index, n_oracles, interval_s, now)
}

/// Pure rotation election: same logic as [`rotation_my_turn`] but the
/// wall-clock `now` is injected so tests can replay any window/elapsed
/// combination deterministically.
///
/// Three regimes depending on fleet size `n`:
///
/// - **n ≤ 2** — primary only, no backup. For n = 2 the staged-backup math
///   `(window_id + 1) % 2` is always "the other operator", so any backup
///   threshold reduces to "after T seconds both operators submit", which
///   defeats the entire rotation.
/// - **3 ≤ n ≤ MAX_SUBMISSIONS (6)** — primary + backup1 at 50 % + backup2
///   at 80 % of `interval_s`. With n ≤ 6 the contract's per-window buffer
///   can absorb every operator if they all piled in at once, so the staged
///   backup only kicks in if the primary is truly missing.
/// - **n > MAX_SUBMISSIONS** — "window-slot" selection. Only a slice of 6
///   consecutive operators (wrapping) is eligible each window, chosen
///   deterministically as indices `[W * 6, W * 6 + 6) mod n` for window W.
///   All 6 eligible ops run `submit_time` at the window start — this
///   provides the redundancy that primary+backup gave at smaller scales,
///   while keeping the on-chain buffer from overflowing and still letting
///   `required_quorum(n)` be met within one window.
pub fn rotation_my_turn_at(
    my_index: usize,
    n_oracles: usize,
    interval_s: u64,
    now: u64,
) -> (bool, u64, u64) {
    let window_id = now / interval_s;
    let elapsed_in_window = now % interval_s;
    let secs_until_next = interval_s - elapsed_in_window;

    let n = n_oracles.max(1);

    if n <= MAX_SUBMISSIONS {
        // Small/medium fleet — primary (+ optional backup) model.
        let primary = (window_id as usize) % n;

        if my_index == primary {
            return (true, window_id, secs_until_next);
        }

        // Backup only for n >= 3 (degenerate at n = 2 — see policy doc above).
        if n >= 3 {
            let backup1_threshold = interval_s * 50 / 100;
            let backup2_threshold = interval_s * 80 / 100;

            if elapsed_in_window >= backup1_threshold {
                let backup1 = ((window_id + 1) as usize) % n;
                if my_index == backup1 {
                    return (true, window_id, secs_until_next);
                }
            }
            if elapsed_in_window >= backup2_threshold {
                let backup2 = ((window_id + 2) as usize) % n;
                if my_index == backup2 {
                    return (true, window_id, secs_until_next);
                }
            }
        }
        (false, window_id, secs_until_next)
    } else {
        // Large fleet — window-slot model. Each window picks a 6-wide
        // contiguous slice (wrapping around the fleet). Every operator in
        // the slice is eligible immediately, so the window easily meets
        // `required_quorum(n)` even with substantial drop-out.
        let base = ((window_id as usize).wrapping_mul(MAX_SUBMISSIONS)) % n;
        let eligible = if base + MAX_SUBMISSIONS <= n {
            my_index >= base && my_index < base + MAX_SUBMISSIONS
        } else {
            // Slice wraps past end of fleet.
            let wrap_end = (base + MAX_SUBMISSIONS) % n;
            my_index >= base || my_index < wrap_end
        };
        (eligible, window_id, secs_until_next)
    }
}

/// Has *anything* already been submitted in the current window?
/// Used to skip a redundant submit after a process restart.
pub fn window_has_submission(last_submit_ts: Option<i64>, interval_s: u64) -> bool {
    match last_submit_ts {
        Some(ts) if ts > 0 => {
            let interval = interval_s.max(1) as i64;
            let last_window = ts / interval;
            let now_window = (unix_secs() as i64) / interval;
            last_window == now_window
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_n1_solo_always_elected() {
        // n=1: solo, always my_turn (window_id % 1 == 0 == my_index)
        let (turn, _, _) = rotation_my_turn_at(0, 1, 300, 1_000_000);
        assert!(turn);
    }

    #[test]
    fn test_rotation_n2_primary_only() {
        // n=2, interval=300s. window_id = 1_000_000 / 300 = 3333,
        // window_id % 2 = 1, so primary = index 1.
        let now = 3333 * 300 + 100; // window_id=3333, elapsed=100s

        // my_index=0 (non-primary): NEVER elects under the new policy,
        // because backup is intentionally disabled at n<=2.
        let (turn, _, _) = rotation_my_turn_at(0, 2, 300, now);
        assert!(!turn, "n=2 non-primary should never elect");

        // my_index=1 (primary): always elects.
        let (turn, _, _) = rotation_my_turn_at(1, 2, 300, now);
        assert!(turn, "n=2 primary should elect");

        // Even at elapsed=250s (well past the OLD 60s threshold) the
        // non-primary still must NOT fire — that was exactly the bug.
        let now = 3333 * 300 + 250;
        let (turn, _, _) = rotation_my_turn_at(0, 2, 300, now);
        assert!(
            !turn,
            "n=2 non-primary at 250s elapsed should still not elect"
        );
    }

    #[test]
    fn test_rotation_n3_backup_thresholds_proportional() {
        // n=3, interval=300s → backup1 at 150s (50%), backup2 at 240s (80%).
        let window_id: u64 = 100;
        let primary = (window_id % 3) as usize; // 1
        let backup1 = ((window_id + 1) % 3) as usize; // 2
        let backup2 = ((window_id + 2) % 3) as usize; // 0

        // elapsed=100s (< 150s): only primary fires.
        let now = window_id * 300 + 100;
        assert!(rotation_my_turn_at(primary, 3, 300, now).0);
        assert!(!rotation_my_turn_at(backup1, 3, 300, now).0);
        assert!(!rotation_my_turn_at(backup2, 3, 300, now).0);

        // elapsed=150s (backup1 threshold reached): primary + backup1.
        let now = window_id * 300 + 150;
        assert!(rotation_my_turn_at(primary, 3, 300, now).0);
        assert!(rotation_my_turn_at(backup1, 3, 300, now).0);
        assert!(!rotation_my_turn_at(backup2, 3, 300, now).0);

        // elapsed=240s (backup2 threshold reached): all three fire.
        let now = window_id * 300 + 240;
        assert!(rotation_my_turn_at(primary, 3, 300, now).0);
        assert!(rotation_my_turn_at(backup1, 3, 300, now).0);
        assert!(rotation_my_turn_at(backup2, 3, 300, now).0);
    }

    #[test]
    fn test_rotation_n5_scaling() {
        // n=5, interval=600s → backup1 at 300s (50%), backup2 at 480s (80%).
        let window_id: u64 = 100;
        let now = window_id * 600 + 300; // elapsed=300s = backup1 threshold
        let primary = (window_id % 5) as usize;
        let backup1 = ((window_id + 1) % 5) as usize;

        assert!(rotation_my_turn_at(primary, 5, 600, now).0);
        assert!(rotation_my_turn_at(backup1, 5, 600, now).0);
        // No other indices fire at this point.
        for idx in 0..5 {
            if idx != primary && idx != backup1 {
                assert!(!rotation_my_turn_at(idx, 5, 600, now).0);
            }
        }
    }

    #[test]
    fn test_rotation_n6_last_small_network() {
        // n = 6 is the LAST fleet size to use primary+backup mode (v0.4 cap).
        let window_id: u64 = 0;
        let now = window_id * 300;
        let primary = (window_id % 6) as usize;
        assert!(rotation_my_turn_at(primary, 6, 300, now).0);
        // At elapsed=0 no backup threshold has been reached yet.
        for idx in 0..6 {
            if idx != primary {
                assert!(!rotation_my_turn_at(idx, 6, 300, now).0);
            }
        }
    }

    #[test]
    fn test_rotation_n7_window_slot_kicks_in() {
        // n = 7 — first fleet size above MAX_SUBMISSIONS = 6, so window-slot
        // mode activates. All 6 ops in the slice fire immediately.
        let window_id: u64 = 0;
        let now = window_id * 300;
        // Window 0 base = 0, slice = [0..6).
        for idx in 0..6 {
            assert!(
                rotation_my_turn_at(idx, 7, 300, now).0,
                "idx {idx} should be in window 0 slice"
            );
        }
        // idx 6 is outside the slice for window 0.
        assert!(!rotation_my_turn_at(6, 7, 300, now).0);
    }

    #[test]
    fn test_rotation_n100_window_slot_wrap() {
        // n=100, MAX_SUBMISSIONS=6:
        //   window 0: base=0,  slice = [0..6)
        //   window 1: base=6,  slice = [6..12)
        //   ...
        //   window 16: base=96, slice = [96..100) ∪ [0..2)  (wraps)
        let w0 = 0u64;
        let now0 = w0 * 300;
        for idx in 0..6 {
            assert!(rotation_my_turn_at(idx, 100, 300, now0).0);
        }
        for idx in 6..100 {
            assert!(!rotation_my_turn_at(idx, 100, 300, now0).0);
        }

        // Window 16: base = (16 * 6) % 100 = 96. Slice = [96..100) ∪ [0..2).
        let w16 = 16u64;
        let now16 = w16 * 300;
        for idx in 96..100 {
            assert!(
                rotation_my_turn_at(idx, 100, 300, now16).0,
                "idx {idx} expected eligible in w16 slice tail"
            );
        }
        for idx in 0..2 {
            assert!(
                rotation_my_turn_at(idx, 100, 300, now16).0,
                "idx {idx} expected eligible in w16 slice wrap"
            );
        }
        for idx in 2..96 {
            assert!(
                !rotation_my_turn_at(idx, 100, 300, now16).0,
                "idx {idx} should NOT be eligible in w16"
            );
        }
    }

    #[test]
    fn test_rotation_n256_window_slot_full_cycle() {
        // n=256 at MAX_OPERATORS. With MAX_SUBMISSIONS=6, a full cycle takes
        // ceil(256/6) = 43 windows (the last one wraps slightly). Within
        // those 43 windows every operator MUST be eligible at least once.
        let mut coverage = [false; 256];
        for w in 0..43u64 {
            let now = w * 300;
            for (idx, c) in coverage.iter_mut().enumerate() {
                if rotation_my_turn_at(idx, 256, 300, now).0 {
                    *c = true;
                }
            }
        }
        assert!(
            coverage.iter().all(|&c| c),
            "every operator should be eligible in at least one of 43 windows"
        );
    }
}
