extern crate alloc;
#[path = "../../src/cbor.rs"] pub mod cbor;
#[path = "../../src/ctap.rs"] pub mod ctap;
#[path = "../../src/ctaphid.rs"] pub mod ctaphid;
use ctap::*;
use rand::RngCore;

#[no_mangle] pub extern "C" fn ctap_new(master: *const u8) -> *mut Ctap {
    let mut m = [0u8; 32]; m.copy_from_slice(unsafe { std::slice::from_raw_parts(master, 32) });
    Box::into_raw(Box::new(Ctap::new(m)))
}
/// returns len>=1, or -1 for NeedUp
#[no_mangle] pub extern "C" fn ctap_handle(c: *mut Ctap, req: *const u8, n: usize, up: i32, out: *mut u8, cap: usize) -> i32 {
    let c = unsafe { &mut *c };
    let req = unsafe { std::slice::from_raw_parts(req, n) };
    let mut rng = |b: &mut [u8]| rand::thread_rng().fill_bytes(b);
    let r = c.handle(req, up != 0, &mut rng);
    let o = unsafe { std::slice::from_raw_parts_mut(out, cap) };
    match r {
        Resp::NeedUp => -1,
        Resp::Err(e) => { o[0] = e; 1 }
        Resp::Ok(v) => { o[..v.len()].copy_from_slice(&v); v.len() as i32 }
    }
}

#[cfg(test)]
mod tests {
    use super::ctaphid::*;
    fn init_pkt(cid: u32, cmd: u8, data: &[u8]) -> Pkt { frames(cid, cmd, data)[0] }
    fn feed(h: &mut Hid, pk: &[Pkt]) -> Vec<Rx> { pk.iter().map(|p| h.rx(p)).collect() }

    #[test] fn init_and_cbor_multipacket() {
        let mut h = Hid::new();
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); p[4] = 0x80 | INIT; p[6] = 8; p[7..15].copy_from_slice(&[1,2,3,4,5,6,7,8]);
        let Rx::Reply(cid, INIT, d) = h.rx(&p) else { panic!() };
        assert_eq!(cid, 0xFFFF_FFFF); assert_eq!(&d[..8], &[1,2,3,4,5,6,7,8]);
        let new = u32::from_be_bytes(d[8..12].try_into().unwrap()); assert_eq!(new, 1); assert_eq!(d[16], 0x0C);
        // 300-byte CBOR message => 1 init + 5 cont
        let msg: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let fr = frames(new, CBOR, &msg); assert_eq!(fr.len(), 1 + (300 - 57 + 58) / 59);
        let rs = feed(&mut h, &fr);
        for r in &rs[..rs.len()-1] { assert!(matches!(r, Rx::None)); }
        let Rx::Cbor(c, got) = rs.into_iter().last().unwrap() else { panic!() };
        assert_eq!(c, new); assert_eq!(got, msg);
        // busy while processing
        let o = init_pkt(77, PING, b"x"); assert!(matches!(h.rx(&o), Rx::Reply(77, ERROR, ref v) if v == &[6]));
        // cancel
        assert!(matches!(h.rx(&init_pkt(new, CANCEL, &[])), Rx::Cancel));
        h.end();
        assert!(matches!(h.rx(&init_pkt(77, PING, b"x")), Rx::Reply(77, PING, _)));
    }
    #[test] fn bad_seq_and_oversize() {
        let mut h = Hid::new();
        let msg = vec![0u8; 200]; let mut fr = frames(5, PING, &msg); fr[1][4] = 3;
        assert!(matches!(h.rx(&fr[0]), Rx::None));
        assert!(matches!(h.rx(&fr[1]), Rx::Reply(5, ERROR, ref v) if v == &[4]));
        let mut p = [0u8; 64]; p[3] = 5; p[4] = 0x80 | CBOR; p[5] = 0x20; // 8192 > MAX
        assert!(matches!(h.rx(&p), Rx::Reply(5, ERROR, ref v) if v == &[3]));
        assert!(matches!(h.rx(&init_pkt(5, MSG, &[0])), Rx::Reply(5, ERROR, ref v) if v == &[1]));
    }
}
