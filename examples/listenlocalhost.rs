fn main() {
    #[cfg(windows)]
    let name = "\\Device\\NPF_Loopback";
    #[cfg(not(windows))]
    let name = "any";
    let mut cap = pcap::Capture::from_device(name)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // filter out all packets that don't have 127.0.0.1 as a source or destination.
    cap.filter("host 127.0.0.1", true).unwrap();

    while let Ok(packet) = cap.next_packet() {
        println!("got packet! {:?}", packet);
    }
}
