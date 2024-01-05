//! STOMP messages

/// A representation of a STOMP frame
#[derive(Debug)]
pub struct Message<T> {
    /// The message content
    pub content: T,
    /// Headers present in the frame which were not required by the content
    pub extra_headers: Vec<(String, String)>,
}

fn pretty_bytes(b: &Option<Vec<u8>>, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    if let Some(v) = b {
        write!(f, "{}", String::from_utf8_lossy(v))
    } else {
        write!(f, "None")
    }
}

/// A STOMP message sent from the server
/// See the [Spec](https://stomp.github.io/stomp-specification-1.2.html) for more information
#[derive(Clone)]
pub enum ServerMessage {
    #[doc(hidden)] // The user shouldn't need to know about this one
    Connected {
        version: String,
        session: Option<String>,
        server: Option<String>,
        heartbeat: Option<(u32, u32)>,
    },
    /// Conveys messages from subscriptions to the client
    Message {
        destination: String,
        message_id: String,
        subscription: String,
        content_type: Option<String>,
        // #[debug(with = "pretty_bytes")]
        body: Option<Vec<u8>>,
    },
    /// Sent from the server to the client once a server has successfully
    /// processed a client frame that requests a receipt
    Receipt { receipt_id: String },
    /// Something went wrong. After sending an Error, the server will close the connection
    Error {
        message: Option<String>,
        content_type: Option<String>,
        // #[debug(with = "pretty_bytes")]
        body: Option<Vec<u8>>,
    },
}

/// A STOMP message sent by the client.
/// See the [Spec](https://stomp.github.io/stomp-specification-1.2.html) for more information
#[derive(Debug, Clone)]
pub enum ClientMessage {
    #[doc(hidden)] // The user shouldn't need to know about this one
    Connect {
        accept_version: String,
        host: String,
        login: Option<String>,
        passcode: Option<String>,
        heartbeat: Option<(u32, u32)>,
    },
    /// Send a message to a destination in the messaging system
    Send {
        destination: String,
        transaction: Option<String>,
        content_type: Option<String>,
        // #[debug(with = "pretty_bytes")]
        body: Option<Vec<u8>>,
    },
    /// Register to listen to a given destination
    Subscribe {
        destination: String,
        id: String,
        ack: Option<AckMode>,
    },
    /// Remove an existing subscription
    Unsubscribe { id: String },
    /// Acknowledge consumption of a message from a subscription using
    /// 'client' or 'client-individual' acknowledgment.
    Ack {
        // TODO ack and nack should be automatic?
        id: String,
        transaction: Option<String>,
    },
    /// Notify the server that the client did not consume the message
    Nack {
        id: String,
        transaction: Option<String>,
    },
    /// Start a transaction
    Begin { transaction: String },
    /// Commit an in-progress transaction
    Commit { transaction: String },
    /// Roll back an in-progress transaction
    Abort { transaction: String },
    /// Gracefully disconnect from the server
    /// Clients MUST NOT send any more frames after the DISCONNECT frame is sent.
    Disconnect { receipt: Option<String> },
}

#[derive(Debug, Clone, Copy)]
pub enum AckMode {
    Auto,
    Client,
    ClientIndividual,
}

use crate::frame::StompFrame;
use crate::message;
use crate::message::ClientMessage::*;
use anyhow::{anyhow, bail, Result};

fn parse_heartbeat(hb: &str) -> Result<(u32, u32)> {
    let mut split = hb.splitn(2, ',');
    let left = split.next().ok_or_else(|| anyhow!("Bad heartbeat"))?;
    let right = split.next().ok_or_else(|| anyhow!("Bad heartbeat"))?;
    Ok((left.parse()?, right.parse()?))
}

fn fetch_header(headers: &Vec<(String, String)>, key: &str) -> Option<String> {
    for (k, ref v) in headers {
        if &*k == key {
            return Some(v.clone());
        }
    }
    None
}

fn expect_header(headers: &Vec<(String, String)>, key: &str) -> Result<String> {
    fetch_header(headers, key).ok_or_else(|| anyhow!("Expected header '{}' missing", key))
}

fn extra_headers(h: &Vec<(String, String)>, expect_keys: &[&str]) -> Vec<(String, String)> {
    h.iter()
        .filter_map(|(k, v)| {
            if expect_keys.contains(&k.as_str()) {
                None
            } else {
                Some((k.clone(), v.clone()))
            }
        })
        .collect()
}

impl<'a> TryFrom<StompFrame<'a>> for Message<message::ClientMessage> {
    type Error = anyhow::Error;

    fn try_from(
        StompFrame {
            command,
            ref headers,
            body,
        }: StompFrame<'a>,
    ) -> std::result::Result<Self, Self::Error> {
        use self::expect_header as eh;
        use self::fetch_header as fh;
        let expect_keys: &[&str];
        let content = match command.to_uppercase().as_ref() {
            "STOMP" | "CONNECT" | "stomp" | "connect" => {
                expect_keys = &["accept-version", "host", "login", "passcode", "heart-beat"];
                let heartbeat = if let Some(hb) = fh(headers, "heart-beat") {
                    Some(parse_heartbeat(&hb)?)
                } else {
                    None
                };
                Connect {
                    accept_version: eh(headers, "accept-version")?,
                    host: eh(headers, "host")?,
                    login: fh(headers, "login"),
                    passcode: fh(headers, "passcode"),
                    heartbeat,
                }
            }
            "DISCONNECT" | "disconnect" => {
                expect_keys = &["receipt"];
                Disconnect {
                    receipt: fh(headers, "receipt"),
                }
            }
            "SEND" | "send" => {
                expect_keys = &[
                    "destination",
                    "transaction",
                    "content-length",
                    "content-type",
                ];
                Send {
                    destination: eh(headers, "destination")?,
                    transaction: fh(headers, "transaction"),
                    content_type: fh(headers, "content-type"),
                    body: body.map(|v| v.to_vec()),
                }
            }
            "SUBSCRIBE" | "subscribe" => {
                expect_keys = &["destination", "id", "ack"];
                Subscribe {
                    destination: eh(headers, "destination")?,
                    id: eh(headers, "id")?,
                    ack: match fh(headers, "ack").as_ref().map(|s| s.as_str()) {
                        Some("auto") => Some(AckMode::Auto),
                        Some("client") => Some(AckMode::Client),
                        Some("client-individual") => Some(AckMode::ClientIndividual),
                        Some(other) => bail!("Invalid ack mode: {}", other),
                        None => None,
                    },
                }
            }
            "UNSUBSCRIBE" | "unsubscribe" => {
                expect_keys = &["id"];
                Unsubscribe {
                    id: eh(headers, "id")?,
                }
            }
            "ACK" | "ack" => {
                expect_keys = &["id", "transaction"];
                Ack {
                    id: eh(headers, "id")?,
                    transaction: fh(headers, "transaction"),
                }
            }
            "NACK" | "nack" => {
                expect_keys = &["id", "transaction"];
                Nack {
                    id: eh(headers, "id")?,
                    transaction: fh(headers, "transaction"),
                }
            }
            "BEGIN" | "begin" => {
                expect_keys = &["transaction"];
                Begin {
                    transaction: eh(headers, "transaction")?,
                }
            }
            "COMMIT" | "commit" => {
                expect_keys = &["transaction"];
                Commit {
                    transaction: eh(headers, "transaction")?,
                }
            }
            "ABORT" | "abort" => {
                expect_keys = &["transaction"];
                Abort {
                    transaction: eh(headers, "transaction")?,
                }
            }
            other => bail!("StompFrame not recognized: {:?}", other),
        };
        let extra_headers: Vec<(String, String)> = extra_headers(headers, expect_keys);
        Ok(Message {
            content,
            extra_headers,
        })
    }
}

impl<'a> TryFrom<StompFrame<'a>> for Message<ServerMessage> {
    type Error = anyhow::Error;

    fn try_from(
        StompFrame {
            command,
            ref headers,
            body,
        }: StompFrame<'a>,
    ) -> std::result::Result<Self, Self::Error> {
        use self::expect_header as eh;
        use self::fetch_header as fh;
        use ServerMessage::{Connected, Error, Message as Msg, Receipt};
        let expect_keys: &[&str];

        let content = match command.to_uppercase().as_ref() {
            "CONNECTED" | "connected" => {
                expect_keys = &["version", "session", "server", "heart-beat"];
                Connected {
                    version: eh(headers, "version")?,
                    session: fh(headers, "session"),
                    server: fh(headers, "server"),
                    heartbeat: match fh(headers, "heart-beat") {
                        Some(hb) => Some(parse_heartbeat(&hb)?),
                        None => None,
                    },
                }
            }
            "MESSAGE" | "message" => {
                expect_keys = &[
                    "destination",
                    "message-id",
                    "subscription",
                    "content-length",
                    "content-type",
                ];
                Msg {
                    destination: eh(headers, "destination")?,
                    message_id: eh(headers, "message-id")?,
                    subscription: eh(headers, "subscription")?,
                    content_type: fh(headers, "content-type"),
                    body: body.map(|v| v.to_vec()),
                }
            }
            "RECEIPT" | "receipt" => {
                expect_keys = &["receipt-id"];
                Receipt {
                    receipt_id: eh(headers, "receipt-id")?,
                }
            }
            "ERROR" | "error" => {
                expect_keys = &["message", "content-length", "content-type"];
                Error {
                    message: fh(headers, "message"),
                    content_type: fh(headers, "content-type"),
                    body: body.map(|v| v.to_vec()),
                }
            }
            other => bail!("StompFrame not recognized: {:?}", other),
        };
        let extra_headers: Vec<(String, String)> = extra_headers(headers, expect_keys);
        Ok(Message {
            content,
            extra_headers,
        })
    }
}
