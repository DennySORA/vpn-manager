//! DNS wire format. Every message is parsed and encoded by hickory-proto; this module only adds
//! the checks a forwarding stub needs (response matches the question, size and count bounds) and
//! never touches names byte by byte.

use std::collections::HashSet;
use std::net::IpAddr;

use hickory_proto::op::{
    Edns, Header, Message, MessageType, Metadata, OpCode, Query, ResponseCode,
};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

/// Largest DNS message on any transport (TCP length prefix, `DoH` body limit).
pub(super) const MAX_MESSAGE: usize = 65_535;
/// EDNS(0) UDP payload we advertise (DNS Flag Day 2020): fits the tunnel MTU unfragmented; larger
/// answers come back truncated and are re-asked over TCP.
pub(super) const EDNS_PAYLOAD: u16 = 1232;
/// Longest CNAME chain followed inside one answer section.
const MAX_CNAME_HOPS: usize = 16;
/// Addresses kept per family from one answer.
const MAX_ADDRS: usize = 32;
/// Smallest encodings of a question (root name, type, class) and a resource record.
const MIN_QUESTION_LEN: usize = 5;
const MIN_RECORD_LEN: usize = 11;

/// One question as asked upstream and as cache / coalescing key: lowercase FQDN, type, class IN.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct Question {
    pub name: Name,
    pub qtype: RecordType,
}

impl Question {
    pub fn new(name: &Name, qtype: RecordType) -> Self {
        let mut name = name.to_lowercase();
        name.set_fqdn(true);
        Self { name, qtype }
    }

    /// Wire-format query: `id`, RD set, one question, an EDNS(0) OPT record (DO clear).
    pub fn encode(&self, id: u16) -> Option<Vec<u8>> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(self.name.clone(), self.qtype));
        msg.set_edns(our_edns());
        msg.to_vec().ok()
    }
}

fn our_edns() -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    edns
}

/// Parses a host given to `resolve`: letters, digits, `-` and `_`, labels of 1..=63 characters,
/// at most 253 characters, one optional trailing dot. IP literals and names whose last label is a
/// number (which URL parsers and `inet_aton` read as an IPv4 address) are rejected.
pub(super) fn parse_hostname(host: &str) -> Option<Name> {
    let h = host.trim_suffix('.');
    if h.is_empty() || h.len() > 253 || h.parse::<IpAddr>().is_ok() {
        return None;
    }
    let mut last = "";
    for label in h.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return None;
        }
        last = label;
    }
    let hex = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_hexdigit()));
    if hex || last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut name = Name::from_ascii(h).ok()?;
    name.set_fqdn(true);
    Some(name.to_lowercase())
}

/// Header counts that cannot fit in `len` bytes mean a hostile or corrupt message; rejecting them
/// before the full parse keeps the parser's allocations proportional to the input.
fn plausible(header: &Header, len: usize) -> bool {
    let c = header.counts;
    let records = usize::from(c.answers) + usize::from(c.authorities) + usize::from(c.additionals);
    12 + usize::from(c.queries) * MIN_QUESTION_LEN + records * MIN_RECORD_LEN <= len
}

/// Why an upstream datagram/message was not accepted as the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reject {
    /// Not parseable as DNS.
    Malformed,
    /// A valid message, but not the response to this query (ID, QR, opcode or question).
    Mismatch,
}

/// Header-only check used for a datagram that may have been cut by the receive buffer.
pub(super) fn is_response_to(bytes: &[u8], id: u16) -> bool {
    Header::from_bytes(bytes)
        .is_ok_and(|h| h.metadata.message_type == MessageType::Response && h.metadata.id == id)
}

/// Accepts `bytes` only if it is a response (QR=1, opcode QUERY) with `id` whose question
/// section is exactly `q`. The RCODE and TC bit are left to the caller.
pub(super) fn check_response(bytes: &[u8], id: u16, q: &Question) -> Result<Message, Reject> {
    if bytes.len() > MAX_MESSAGE {
        return Err(Reject::Malformed);
    }
    let header = Header::from_bytes(bytes).map_err(|_| Reject::Malformed)?;
    if header.metadata.message_type != MessageType::Response || header.metadata.id != id {
        return Err(Reject::Mismatch);
    }
    if !plausible(&header, bytes.len()) {
        return Err(Reject::Malformed);
    }
    let msg = Message::from_vec(bytes).map_err(|_| Reject::Malformed)?;
    if msg.metadata.op_code != OpCode::Query {
        return Err(Reject::Mismatch);
    }
    let wanted_type = q.qtype;
    match msg.queries.as_slice() {
        [only]
            if only.name == q.name
                && only.query_type == wanted_type
                && only.query_class == DNSClass::IN =>
        {
            Ok(msg)
        }
        _ => Err(Reject::Mismatch),
    }
}

/// RCODEs that are an answer about the name; anything else is a failure of that server.
pub(super) const fn is_answer(rcode: ResponseCode) -> bool {
    matches!(rcode, ResponseCode::NoError | ResponseCode::NXDomain)
}

/// A/AAAA addresses of the question's name, following CNAMEs inside the answer section. Records
/// owned by unrelated names are ignored.
pub(super) fn addresses(msg: &Message, q: &Question) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if !matches!(q.qtype, RecordType::A | RecordType::AAAA) {
        return out;
    }
    let mut owner = q.name.clone();
    for _ in 0..MAX_CNAME_HOPS {
        let mut next = None;
        for r in msg
            .answers
            .iter()
            .filter(|r| r.dns_class == DNSClass::IN && r.name == owner)
        {
            match &r.data {
                RData::A(a) if q.qtype == RecordType::A => out.push(IpAddr::V4(a.0)),
                RData::AAAA(a) if q.qtype == RecordType::AAAA => out.push(IpAddr::V6(a.0)),
                RData::CNAME(c) => next = Some(c.0.clone()),
                _ => {}
            }
        }
        match next {
            Some(target) if out.is_empty() => owner = target,
            _ => break,
        }
    }
    let mut seen = HashSet::new();
    out.retain(|ip| seen.insert(*ip));
    out.truncate(MAX_ADDRS);
    out
}

/// Whether the answer carries data for the question (otherwise it is NODATA, cached negatively).
pub(super) fn has_data(msg: &Message, q: &Question, addrs: &[IpAddr]) -> bool {
    match q.qtype {
        RecordType::A | RecordType::AAAA => !addrs.is_empty(),
        RecordType::ANY => !msg.answers.is_empty(),
        t => msg.answers.iter().any(|r| r.record_type() == t),
    }
}

/// Smallest TTL of the answer section.
pub(super) fn min_answer_ttl(msg: &Message) -> Option<u32> {
    msg.answers.iter().map(|r| r.ttl).min()
}

/// A query received by `query_message`, already vetted.
pub(super) enum Request {
    /// Forward (or answer from cache) this question; reply to `Message`'s ID.
    Ask(Box<Message>, Question),
    /// Answer locally with this response (FORMERR, NOTIMP, REFUSED).
    Reply(Vec<u8>),
    /// Not a query at all (garbage or a response): nothing to answer.
    Ignore,
}

pub(super) fn parse_request(bytes: &[u8]) -> Request {
    if bytes.len() > MAX_MESSAGE {
        return Request::Ignore;
    }
    let Ok(header) = Header::from_bytes(bytes) else {
        return Request::Ignore;
    };
    if header.metadata.message_type != MessageType::Query {
        return Request::Ignore;
    }
    let local = |req: Option<&Message>, rcode| {
        local_response(&header.metadata, req, rcode).map_or(Request::Ignore, Request::Reply)
    };
    if !plausible(&header, bytes.len()) {
        return local(None, ResponseCode::FormErr);
    }
    let Ok(req) = Message::from_vec(bytes) else {
        return local(None, ResponseCode::FormErr);
    };
    if req.metadata.op_code != OpCode::Query {
        return local(Some(&req), ResponseCode::NotImp);
    }
    let [q] = req.queries.as_slice() else {
        return local(Some(&req), ResponseCode::FormErr);
    };
    if q.query_class != DNSClass::IN
        || matches!(
            q.query_type,
            RecordType::AXFR | RecordType::IXFR | RecordType::OPT | RecordType::TSIG
        )
    {
        return local(Some(&req), ResponseCode::Refused);
    }
    let question = Question::new(&q.name, q.query_type);
    Request::Ask(Box::new(req), question)
}

fn response_shell(meta: &Metadata, req: Option<&Message>, rcode: ResponseCode) -> Message {
    let mut resp = Message::response(meta.id, meta.op_code);
    resp.metadata.recursion_desired = meta.recursion_desired;
    resp.metadata.checking_disabled = meta.checking_disabled;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = rcode;
    if let Some(req) = req {
        if req.queries.len() == 1 {
            resp.add_queries(req.queries.iter().cloned());
        }
        if req.edns.is_some() {
            resp.set_edns(our_edns());
        }
    }
    resp
}

fn local_response(meta: &Metadata, req: Option<&Message>, rcode: ResponseCode) -> Option<Vec<u8>> {
    response_shell(meta, req, rcode).to_vec().ok()
}

/// NOERROR without an answer (NODATA) to `req`: the name may exist, but has no address of a
/// family this connection can use.
pub(super) fn no_data(req: &Message) -> Option<Vec<u8>> {
    local_response(&req.metadata, Some(req), ResponseCode::NoError)
}

/// A local answer with `rcode` (SERVFAIL, REFUSED) to a raw query; `None` if it is no query.
pub(super) fn error_response(request: &[u8], rcode: ResponseCode) -> Option<Vec<u8>> {
    if request.len() > MAX_MESSAGE {
        return None;
    }
    let header = Header::from_bytes(request).ok()?;
    if header.metadata.message_type != MessageType::Query {
        return None;
    }
    let req = plausible(&header, request.len())
        .then(|| Message::from_vec(request).ok())
        .flatten();
    local_response(&header.metadata, req.as_ref(), rcode)
}

/// The largest UDP response the client of `request` accepts: 512 bytes without EDNS, its
/// advertised payload size (at most 4096) with it.
pub(super) fn udp_limit(request: &[u8]) -> usize {
    Message::from_vec(request)
        .ok()
        .and_then(|m| m.edns.map(|e| usize::from(e.max_payload())))
        .unwrap_or(512)
        .clamp(512, 4096)
}

/// `response` cut down to its header, question and OPT record with TC set, telling a UDP client
/// to ask again over TCP.
pub(super) fn truncated(response: &[u8]) -> Option<Vec<u8>> {
    let mut msg = Message::from_vec(response).ok()?;
    msg.metadata.truncation = true;
    msg.answers.clear();
    msg.authorities.clear();
    msg.additionals.clear();
    msg.to_vec().ok()
}

/// The client's response built from a validated upstream answer: the client's ID, flags and
/// question (case preserved), the upstream RCODE, answer and authority sections with TTLs aged
/// by `elapsed` and capped at the answer's `remaining` cache lifetime. Additional records are
/// dropped; an OPT record is added if the client sent one.
pub(super) fn client_response(
    req: &Message,
    upstream: &[u8],
    elapsed: u32,
    remaining: u32,
) -> Option<Vec<u8>> {
    let up = Message::from_vec(upstream).ok()?;
    let mut resp = response_shell(&req.metadata, Some(req), up.metadata.response_code);
    let age = |mut r: Record| {
        r.ttl = r.ttl.saturating_sub(elapsed).min(remaining);
        r
    };
    resp.add_answers(up.answers.into_iter().map(age));
    resp.add_authorities(up.authorities.into_iter().map(age));
    let bytes = resp.to_vec().ok()?;
    (bytes.len() <= MAX_MESSAGE).then_some(bytes)
}
