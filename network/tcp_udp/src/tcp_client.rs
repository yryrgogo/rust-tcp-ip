use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::str;

pub fn connect(address: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect(address)?;
    loop {
        let mut input = String::new();
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        handle.read_line(&mut input)?;
        stream.write_all(input.as_bytes())?;
        let mut reader = BufReader::new(&stream);
        let mut buffer = Vec::new();
        reader.read_until(b'\n', &mut buffer)?;
        print!("{}", str::from_utf8(&buffer).unwrap());
    }
}
