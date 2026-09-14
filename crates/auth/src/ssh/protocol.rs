//! SSH agent protocol helpers.
//!
//! Reference docs:
//! - <https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent>
//! - <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent>

use std::io::{self, Error, ErrorKind};

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};

use super::agent::AgentIdentity;

const SSH_ED25519_ALGORITHM: &str = "ssh-ed25519";
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_AGENT_FRAME_SIZE: usize = 1 << 20;

/// Generic SSH agent failure response message code.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// SSH agent request code for listing available identities.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// SSH agent response code for returning identities.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// SSH agent request code for signing data with a key.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// SSH agent response code for returning a signature.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Parsed fields from an SSH agent sign request.
#[derive(Debug)]
pub struct AgentSignRequest {
    /// Requested public key blob in OpenSSH wire format.
    pub public_key_blob: Vec<u8>,
    /// Raw payload bytes to sign.
    pub data: Vec<u8>,
}

/// Encodes an SSH agent packet with the given message type and payload.
pub fn encode_agent_frame(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 1 + payload.len());
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(message_type);
    frame.extend_from_slice(payload);
    frame
}

/// Reads one SSH agent frame from a Unix stream with a bounded size and timeout.
pub(crate) async fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0u8; 4];
    match read_exact_with_deadline(stream, &mut length_bytes).await {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }

    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_AGENT_FRAME_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "SSH agent frame exceeds maximum size",
        ));
    }

    let mut body = vec![0u8; length];
    read_exact_with_deadline(stream, &mut body).await?;

    let mut frame = length_bytes.to_vec();
    frame.extend_from_slice(&body);
    Ok(Some(frame))
}

/// Writes one SSH agent frame to a Unix stream with a timeout.
pub(crate) async fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> io::Result<()> {
    match timeout(CONNECTION_IO_TIMEOUT, stream.write_all(frame)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Error::from(ErrorKind::TimedOut)),
    }
}

/// Encodes an `SSH_AGENT_IDENTITIES_ANSWER` packet for all available identities.
pub fn encode_request_identities_response(identities: &[AgentIdentity]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for identity in identities {
        payload = encode_string(&identity.public_key.blob(), payload);
        payload = encode_string(identity.comment.as_bytes(), payload);
    }
    encode_agent_frame(SSH_AGENT_IDENTITIES_ANSWER, &payload)
}

/// Parses the fields from a `SSH_AGENTC_SIGN_REQUEST` frame.
pub fn parse_sign_request_frame(frame: &[u8]) -> Result<AgentSignRequest> {
    let (message_type, payload) = parse_agent_frame(frame)?;
    if message_type != SSH_AGENTC_SIGN_REQUEST {
        return Err(anyhow!(
            "unsupported SSH agent message type: {message_type}"
        ));
    }

    let mut cursor = payload;
    let public_key_blob = read_ssh_bytes(&mut cursor)?;
    let data = read_ssh_bytes(&mut cursor)?;
    read_u32(&mut cursor)?;

    if !cursor.is_empty() {
        return Err(anyhow!("unexpected trailing SSH agent sign request data"));
    }

    Ok(AgentSignRequest {
        public_key_blob,
        data,
    })
}

/// Encodes a `SSH_AGENT_SIGN_RESPONSE` packet for a 64-byte Ed25519 signature.
pub fn encode_sign_response(signature: &[u8; 64]) -> Vec<u8> {
    let mut signature_blob = Vec::new();
    signature_blob = encode_string(SSH_ED25519_ALGORITHM.as_bytes(), signature_blob);
    signature_blob = encode_string(signature, signature_blob);

    let mut payload = Vec::new();
    payload = encode_string(&signature_blob, payload);
    encode_agent_frame(SSH_AGENT_SIGN_RESPONSE, &payload)
}

async fn read_exact_with_deadline(stream: &mut UnixStream, buf: &mut [u8]) -> io::Result<()> {
    match timeout(CONNECTION_IO_TIMEOUT, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Error::from(ErrorKind::TimedOut)),
    }
}

fn encode_string(bytes: &[u8], mut output: Vec<u8>) -> Vec<u8> {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

fn parse_agent_frame(frame: &[u8]) -> Result<(u8, &[u8])> {
    let Some((length, payload)) = frame.split_first_chunk::<4>() else {
        return Err(anyhow!("truncated SSH agent frame length"));
    };
    let length = u32::from_be_bytes(*length) as usize;
    if payload.len() < length {
        return Err(anyhow!("truncated SSH agent frame payload"));
    }
    if payload.len() != length {
        return Err(anyhow!("unexpected trailing bytes in SSH agent frame"));
    }
    let Some((kind, body)) = payload.split_first() else {
        return Err(anyhow!("truncated SSH agent frame payload"));
    };

    Ok((*kind, body))
}

fn read_ssh_bytes(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    let Some((length, rest)) = cursor.split_first_chunk::<4>() else {
        return Err(anyhow!("truncated SSH string length"));
    };
    *cursor = rest;

    let length = u32::from_be_bytes(*length) as usize;
    if cursor.len() < length {
        return Err(anyhow!("truncated SSH string body"));
    }

    let value = cursor[..length].to_vec();
    *cursor = &cursor[length..];
    Ok(value)
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32> {
    let Some((value, rest)) = cursor.split_first_chunk::<4>() else {
        return Err(anyhow!("truncated SSH agent unsigned 32-bit integer"));
    };
    *cursor = rest;
    Ok(u32::from_be_bytes(*value))
}
