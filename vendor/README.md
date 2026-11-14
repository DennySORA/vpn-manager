# Patched third-party sources

Crates here replace their crates.io release through `[patch.crates-io]` in the workspace
`Cargo.toml`. Each is the published package as is plus a small, documented patch: compare with the
registry copy (`diff -ru ~/.cargo/registry/src/*/smoltcp-0.14.0 vendor/smoltcp`) to see exactly
what differs. They are not workspace members (`exclude`), so workspace lints and tests do not run
on them.

## smoltcp 0.14.0

Source: crates.io `smoltcp` 0.14.0 (upstream commit `cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3`,
0BSD), vendored unmodified in its own commit; the three patches below touch only
`src/socket/tcp.rs` and `src/storage/ring_buffer.rs`. Patches 1 and 2 fix bugs that no smoltcp
release (0.14.0 is the latest) and not upstream `main` (checked 2026-11-02) fixes; patch 3 adds
what the netstack needs to enlarge the buffers of an open connection.

Both bugs stranded TCP flows of the userspace netstack. The benchmark's 500-flow load found them
(0.2–2 % of the flows stopped moving, 11 with 50 ms added RTT); `crates/tunnel` reproduces them:
`netstack::tests` deterministically, `tests/loopback_pair.rs` (`many_flows_repeatedly`) with
hundreds of flows over a delayed, lossy path.

### 1. Retransmission timeouts on both ends: ACKs at a rewound sequence number

On a retransmission timeout smoltcp rewinds `remote_last_seq` (SND.NXT) to `local_seq_no`
(SND.UNA) to resend everything (go-back-N), and every later segment without payload (ACK, window
update, RST, the ACK replies of `process()`) carried that rewound number. When the remote already
has the data and only its ACKs were lost, the rewound number lies left of the remote's window: the
remote answers and drops the segment unread (RFC 9293 3.10.7.4), ACK field included. Once both
ends are in that state, both retransmit data the other already has, neither ever learns that its
own data arrived, and the connection hangs both ways until the dead-peer timeout (5 minutes):
`remote_last_ts` does not advance either, since the segments are dropped before it is updated.

Evidence (socket dump of a stuck flow, client ⇄ server): each end in RTO recovery (RTO 16 s, cwnd
one MSS); the server had received 7 243 bytes beyond the client's SND.UNA and the client 2 760
beyond the server's; neither had processed a segment from the other since the flow stopped.

Patch: a `remote_max_seq` (SND.MAX) that a timeout does not rewind; zero-length segments from
`dispatch()` (on the wire only, the state keeps the rewind) and `ack_reply()` carry it, as BSD's
`tcp_output` does with `snd_max`.

### 2. Fast retransmit of a lone FIN sent nothing and disarmed the timer

Three duplicate ACKs replace the retransmit timer with fast retransmit. When it fired, `dispatch()`
set `pending_fast_retransmit` and the timer to idle, but `seq_to_transmit()` only honoured the
pending retransmission while data was queued: with just a FIN in flight nothing went out, and
nothing would ever resend the FIN. The peer waited for the end of the stream until a keep-alive
(60 s), or forever without keep-alives. With patch 1 alone, 6 flows in 21 repeated runs still
stopped, all at the end of the stream; the 3 dumped were all this: server in `Closing`, FIN
unacknowledged, timer idle, `pending_fast_retransmit` true, 3–7 duplicate ACKs.

Patch: a pending fast retransmission is also sent when only a FIN is in flight, and the flag is
cleared only once the segment was emitted (as upstream did in `bd424c84`), so a fast
retransmission the device could not take is retried.

### 3. TCP buffers that grow while the connection uses them

A smoltcp socket keeps the two buffers it was created with. The netstack sizes every tunnel TCP
connection from its transport profile (docs/architecture.md §4.5): it opens small and its buffers
are enlarged only while the connection really carries enough to need them, so that a large upper
size costs nothing for the connections that stay idle or slow. That needs two things smoltcp does
not offer.

Patch:

- `RingBuffer::grow` (`src/storage/ring_buffer.rs`) replaces the storage with a larger one and
  copies the whole old storage in logical order, so every byte keeps its distance from the read
  position — the unread data, and in a receive buffer also the segments that arrived out of order,
  which smoltcp stores in the unallocated part.
- `Socket::grow_rx_buffer` and `Socket::grow_tx_buffer` (`src/socket/tcp.rs`) call it; the transmit
  side wakes a writer that waited for room.
- `Socket::set_rx_capacity_limit`: the window scale is fixed by the SYN, computed from the receive
  buffer's size. A closed socket can be told the size its buffer may grow to, and offers the scale
  for that size (`local_win_shift`, also used when the socket is reset), so the window it offers
  later can follow the buffer.

Nothing else changes: a socket whose buffers never grow and that is given no limit behaves as
before. `crates/tunnel` checks it in `netstack::tests`
(`a_stream_is_carried_intact_while_its_buffers_grow`): both buffers are enlarged while the sender
holds unacknowledged data and the receiver holds data that arrived out of order behind a missing
segment; every byte comes out as it went in.

### Removing the patch

Patches 1 and 2 are bug fixes; patch 3 is a capability the netstack needs. When a smoltcp release
fixes both bugs and can enlarge the buffers of an open socket, depend on it, delete
`[patch.crates-io]`, the `exclude` entry and this directory, and keep the regression tests (`both_ends_recover_after_a_timeout_that_lost_every_ack`,
`a_lost_fin_is_resent_by_fast_retransmit`, `hundreds_of_flows_finish_over_a_delayed_lossy_path`)
passing.
