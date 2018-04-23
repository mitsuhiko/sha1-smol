extern crate sha1;
extern crate ring;
extern crate openssl;
extern crate crypto;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::time::{Instant, Duration};
use std::process::{Command, Stdio};

use crypto::digest::Digest;

fn time<F, FMT>(desc: &str, f: F, fmt: FMT)
    where F: Fn(),
          FMT: Fn(Duration) -> String
{
    let start = Instant::now();
    f();
    let duration = Instant::now() - start;
    println!("{}: {}", desc, fmt(duration));
}

fn to_hex(bytes : &[u8]) -> String {
    let hex_bytes : Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    hex_bytes.join("")
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let mut out = Vec::<u8>::new();

    if args.len() == 1 {
        std::io::stdin().read_to_end(&mut out).unwrap();
    } else if args.len() == 2 {
        let mut f = fs::File::open(&args[1]).unwrap();
        f.read_to_end(&mut out).unwrap();
    } else {
        panic!("wrong argument count");
    }

    let throughput = |duration: Duration| {
        let s = duration.as_secs() as f64;
        let ns = duration.subsec_nanos() as f64 / 1000000000.0;
        format!("{:.2} MB/s", out.len() as f64 / (s + ns) / 1000000.0)
    };

    if env::var("WITHOUT_SHA1SUM") != Ok("1".into()) {
        time("sha1sum program",
             || {
            let mut child = Command::new("sha1sum")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            if let Some(ref mut stdin) = child.stdin {
                stdin.write(&out).unwrap();
            }
            child.wait().unwrap();
        },
             &throughput);
    }

    time("sha1 crate",
         || {
             let mut sha1 = sha1::Sha1::new();
             sha1.update(&out);
             println!("sha1: {}", sha1.digest());
         },
         &throughput);

    time("ring crate",
         || {
             let digest = ring::digest::digest(&ring::digest::SHA1, &out);
             println!("ring: {:?}", digest);
         },
         &throughput);

    time("openssl crate", || {
             let digest = openssl::sha::sha1(&out);
             println!("openssl: {}", to_hex(&digest));
         },
         &throughput);

    time("crypto crate",
         || {
             let mut hasher = crypto::sha1::Sha1::new();
             hasher.input(&out);
             let digest = hasher.result_str();
             println!("crypto: {}", digest);
         },
         &throughput);
}
