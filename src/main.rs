extern crate futures;
extern crate tokio_core;
extern crate native_tls;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_native_tls;

use std::{ io, env };
use std::net::{ SocketAddr, SocketAddrV4, Ipv4Addr };
use futures::Future;
use tokio_core::reactor::Core;
use native_tls::Certificate;
use trust_dns::op::Query;
use trust_dns::rr::{ Name, RecordType };
use trust_dns::client::ClientFuture;
use trust_dns_proto::DnsHandle;
use trust_dns_native_tls::TlsClientStreamBuilder;


const DNS_QUAD9_NET: &[u8] = include_bytes!("dnsquad9net.crt");

fn main() {
    let target = env::args().nth(1).unwrap();
    start(&target).unwrap()
}

#[inline]
fn start(target: &str) -> io::Result<()> {
    let mut core = Core::new()?;
    let handle = core.handle();

    let host = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 853));
    let target = Name::parse(target, None)?;

    let mut builder = TlsClientStreamBuilder::new();
    builder.add_ca(Certificate::from_der(DNS_QUAD9_NET)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?
    );
    let (fut, han) = builder.build(host, String::from("dns.quad9.net"), &handle);

    let mut client = ClientFuture::new(fut, han, &handle, None);
    let fut = client.lookup(Query::query(target, RecordType::A))
        .map(|msg| for record in msg.answers() {
            if let Some(ip) = record.rdata().to_ip_addr() {
                println!("{}", ip);
            }
        });

    core.run(fut).unwrap();
    Ok(())
}
