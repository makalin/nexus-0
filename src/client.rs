//! Framed IPC client used by examples and tests.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::schema::{decode_response, encode_request, Request, Response, REQUEST_HEADER_LEN};

pub fn call(bind: &str, req: &Request) -> io::Result<Response> {
    let mut stream = connect(bind)?;
    let mut buf = Vec::new();
    encode_request(req, &mut buf);
    stream.write_all(&buf)?;
    stream.flush()?;
    read_response(&mut stream)
}

pub fn connect(bind: &str) -> io::Result<Stream> {
    if is_tcp(bind) {
        return Ok(Stream::Tcp(TcpStream::connect(bind)?));
    }
    #[cfg(unix)]
    {
        Ok(Stream::Unix(std::os::unix::net::UnixStream::connect(bind)?))
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unix socket '{bind}' is not available on this platform; use host:port"),
        ))
    }
}

pub fn is_tcp(bind: &str) -> bool {
    bind.parse::<std::net::SocketAddr>().is_ok()
}

pub enum Stream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Stream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Stream::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Stream::Unix(s) => s.flush(),
        }
    }
}

pub fn read_response<R: Read>(stream: &mut R) -> io::Result<Response> {
    let mut header = [0u8; crate::schema::RESPONSE_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let span_count = u16::from_le_bytes([header[40], header[41]]) as usize;
    let plen = u32::from_le_bytes(header[42..46].try_into().unwrap()) as usize;
    let extra = span_count
        .checked_mul(crate::schema::SPAN_WIRE_LEN)
        .and_then(|s| s.checked_add(plen))
        .and_then(|s| {
            if header[46] != 0 {
                s.checked_add(crate::schema::TOOL_BLOCK_LEN)
            } else {
                Some(s)
            }
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
    let mut body = vec![0u8; extra];
    if extra > 0 {
        stream.read_exact(&mut body)?;
    }
    let mut all = header.to_vec();
    all.extend_from_slice(&body);
    decode_response(&all).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn write_request<W: Write>(stream: &mut W, req: &Request) -> io::Result<()> {
    let mut buf = Vec::with_capacity(REQUEST_HEADER_LEN + req.payload.len());
    encode_request(req, &mut buf);
    stream.write_all(&buf)?;
    stream.flush()
}
