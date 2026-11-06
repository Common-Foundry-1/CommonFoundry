//! Submit one deterministic share to a loopback compact-proof testnet pool.
//! The pilot pool uses a zero-bit share target; normal pool mining uses the GPU miner.

use cmfd_node::pool::{PoolClient, PoolClientConfig};
use std::net::SocketAddr;

fn decode_32(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut result = [0_u8; 32];
    hex::decode_to_slice(value, &mut result)?;
    Ok(result)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let address: SocketAddr = arguments
        .next()
        .ok_or("pool address is required")?
        .parse()?;
    let pin = decode_32(&arguments.next().ok_or("certificate pin is required")?)?;
    let payout = decode_32(&arguments.next().ok_or("payout key is required")?)?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let config = PoolClientConfig::compiled_network_address_only(
        address,
        pin,
        "compact-proof-pilot",
        payout,
    )?;
    let mut client = PoolClient::connect(config)?;
    let job = client.current_job().clone();
    println!(
        "connected network={} height={} share_target={}",
        hex::encode(job.challenge.network_id),
        job.challenge.height,
        hex::encode(job.share_target)
    );
    let result = client.submit_share(job.job_id, 0)?;
    println!("share_result={result:?}");
    Ok(())
}
