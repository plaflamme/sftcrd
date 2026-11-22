//! Integration tests exercising the exported PC/SC-Lite IFD Handler v3 C ABI
//! against a mock Unix domain socket server.

use std::ffi::CString;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use sftcrd_ifd::abi::{
    Dword, IFD_ERROR_INSUFFICIENT_BUFFER, IFD_ERROR_TAG, IFD_ICC_NOT_PRESENT, IFD_ICC_PRESENT,
    IFD_NOT_SUPPORTED, IFD_POWER_DOWN, IFD_POWER_UP, IFD_PROTOCOL_NOT_SUPPORTED, IFD_RESET,
    IFD_SUCCESS, MAX_ATR_SIZE, SCARD_PROTOCOL_T1, SCardIoHeader, TAG_IFD_ATR,
    TAG_IFD_SLOTS_NUMBER,
};
use sftcrd_ifd::{
    IFDHCloseChannel, IFDHControl, IFDHCreateChannelByName, IFDHGetCapabilities, IFDHICCPresence,
    IFDHPowerICC, IFDHSetCapabilities, IFDHSetProtocolParameters, IFDHTransmitToICC,
};
use sftcrd_ifd_proto::{ErrorCode, Request, Response, read_request, write_response};

const MOCK_ATR: &[u8] = &[0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31];

fn unique_socket_path(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sftcrd-ifd-test-{label}-{}-{n}.sock",
        std::process::id()
    ))
}

fn spawn_mock_server(
    sock_path: &Path,
    max_connections: usize,
    present: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    let _ = std::fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path).expect("bind mock socket");
    thread::spawn(move || {
        for _ in 0..max_connections {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut powered = false;
            while let Ok(Some(req)) = read_request(&mut stream) {
                let resp = match req {
                    Request::Presence => Response::Presence(present.load(Ordering::SeqCst)),
                    Request::PowerOn | Request::Reset => {
                        powered = true;
                        Response::Atr(MOCK_ATR.to_vec())
                    }
                    Request::PowerOff => {
                        powered = false;
                        Response::Ok
                    }
                    Request::GetAtr => Response::Atr(MOCK_ATR.to_vec()),
                    Request::Transmit(apdu) => {
                        if powered {
                            // Echo payload + 90 00, or return 512 bytes for extended test.
                            if apdu.len() > 256 {
                                let mut out = vec![0xAB; 512];
                                out.extend_from_slice(&[0x90, 0x00]);
                                Response::Apdu(out)
                            } else {
                                let mut out = apdu;
                                out.extend_from_slice(&[0x90, 0x00]);
                                Response::Apdu(out)
                            }
                        } else {
                            Response::error(ErrorCode::NotPowered, "card not powered")
                        }
                    }
                };
                if write_response(&mut stream, &resp).is_err() {
                    break;
                }
            }
        }
    })
}

#[test]
fn ifdh_lifecycle_and_capabilities() {
    let sock_path = unique_socket_path("lifecycle");
    let present = Arc::new(AtomicBool::new(true));
    let server = spawn_mock_server(&sock_path, 1, Arc::clone(&present));
    let lun: Dword = 0x0001_0000;

    let dev = CString::new(sock_path.to_str().expect("utf8 path")).expect("CString");
    assert_eq!(
        unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
        IFD_SUCCESS
    );
    assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);

    let mut val = [0u8; MAX_ATR_SIZE];
    let mut len: Dword = 1;
    assert_eq!(
        unsafe { IFDHGetCapabilities(lun, TAG_IFD_SLOTS_NUMBER, &raw mut len, val.as_mut_ptr()) },
        IFD_SUCCESS
    );
    assert_eq!((len, val[0]), (1, 1));
    assert_eq!(
        unsafe { IFDHGetCapabilities(lun, 0x9999, &raw mut len, val.as_mut_ptr()) },
        IFD_ERROR_TAG
    );
    assert_eq!(
        unsafe { IFDHSetCapabilities(lun, TAG_IFD_ATR, 0, ptr::null_mut()) },
        IFD_ERROR_TAG
    );

    assert_eq!(
        IFDHSetProtocolParameters(lun, SCARD_PROTOCOL_T1, 0, 0, 0, 0),
        IFD_SUCCESS
    );
    assert_eq!(
        IFDHSetProtocolParameters(lun, 0x0008, 0, 0, 0, 0),
        IFD_PROTOCOL_NOT_SUPPORTED
    );

    let mut atr = [0u8; MAX_ATR_SIZE];
    let mut atr_len: Dword = 0;
    assert_eq!(
        unsafe { IFDHPowerICC(lun, IFD_POWER_UP, atr.as_mut_ptr(), &raw mut atr_len) },
        IFD_SUCCESS
    );
    assert_eq!(&atr[..usize::try_from(atr_len).unwrap()], MOCK_ATR);

    let mut small_len: Dword = 2;
    assert_eq!(
        unsafe { IFDHGetCapabilities(lun, TAG_IFD_ATR, &raw mut small_len, val.as_mut_ptr()) },
        IFD_ERROR_INSUFFICIENT_BUFFER
    );
    let mut atr_cap: Dword = Dword::try_from(MAX_ATR_SIZE).unwrap();
    assert_eq!(
        unsafe { IFDHGetCapabilities(lun, TAG_IFD_ATR, &raw mut atr_cap, val.as_mut_ptr()) },
        IFD_SUCCESS
    );
    assert_eq!(&val[..usize::try_from(atr_cap).unwrap()], MOCK_ATR);

    let mut ctrl_ret: Dword = 99;
    assert_eq!(
        unsafe {
            IFDHControl(
                lun,
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &raw mut ctrl_ret,
            )
        },
        IFD_NOT_SUPPORTED
    );
    assert_eq!(ctrl_ret, 0);

    assert_eq!(
        unsafe { IFDHPowerICC(lun, IFD_POWER_DOWN, atr.as_mut_ptr(), &raw mut atr_len) },
        IFD_SUCCESS
    );
    assert_eq!(atr_len, 0);
    assert_eq!(
        unsafe { IFDHPowerICC(lun, IFD_RESET, atr.as_mut_ptr(), &raw mut atr_len) },
        IFD_SUCCESS
    );
    assert_eq!(&atr[..usize::try_from(atr_len).unwrap()], MOCK_ATR);

    assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
    server.join().expect("mock server thread");
    let _ = std::fs::remove_file(&sock_path);
}

#[test]
fn ifdh_transmit_short_extended_and_bounds() {
    let sock_path = unique_socket_path("transmit");
    let present = Arc::new(AtomicBool::new(true));
    let server = spawn_mock_server(&sock_path, 1, Arc::clone(&present));
    let lun: Dword = 0x0003_0000;

    let dev = CString::new(sock_path.to_str().expect("utf8 path")).expect("CString");
    assert_eq!(
        unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
        IFD_SUCCESS
    );
    let mut atr = [0u8; MAX_ATR_SIZE];
    let mut atr_len: Dword = 0;
    assert_eq!(
        unsafe { IFDHPowerICC(lun, IFD_POWER_UP, atr.as_mut_ptr(), &raw mut atr_len) },
        IFD_SUCCESS
    );

    let send_pci = SCardIoHeader {
        protocol: SCARD_PROTOCOL_T1,
        length: 0,
    };
    let mut tx = [0x00u8, 0xA4, 0x04, 0x00];
    let mut rx = [0u8; 64];
    let mut rx_len: Dword = 64;
    let mut recv_pci = SCardIoHeader::default();
    assert_eq!(
        unsafe {
            IFDHTransmitToICC(
                lun,
                send_pci,
                tx.as_mut_ptr(),
                Dword::try_from(tx.len()).unwrap(),
                rx.as_mut_ptr(),
                &raw mut rx_len,
                &raw mut recv_pci,
            )
        },
        IFD_SUCCESS
    );
    assert_eq!(
        &rx[..usize::try_from(rx_len).unwrap()],
        &[0x00, 0xA4, 0x04, 0x00, 0x90, 0x00]
    );
    assert_eq!(recv_pci.protocol, SCARD_PROTOCOL_T1);

    // Extended-length APDU: insufficient buffer fails cleanly with *rx_length = 0.
    let mut big_tx = vec![0x42u8; 400];
    let mut tiny_rx = [0u8; 4];
    let mut tiny_len: Dword = 4;
    assert_eq!(
        unsafe {
            IFDHTransmitToICC(
                lun,
                send_pci,
                big_tx.as_mut_ptr(),
                Dword::try_from(big_tx.len()).unwrap(),
                tiny_rx.as_mut_ptr(),
                &raw mut tiny_len,
                ptr::null_mut(),
            )
        },
        IFD_ERROR_INSUFFICIENT_BUFFER
    );
    assert_eq!(tiny_len, 0);

    let mut big_rx = vec![0u8; 1024];
    let mut big_rx_len: Dword = 1024;
    assert_eq!(
        unsafe {
            IFDHTransmitToICC(
                lun,
                send_pci,
                big_tx.as_mut_ptr(),
                Dword::try_from(big_tx.len()).unwrap(),
                big_rx.as_mut_ptr(),
                &raw mut big_rx_len,
                ptr::null_mut(),
            )
        },
        IFD_SUCCESS
    );
    assert_eq!(big_rx_len, 514);
    assert!(big_rx[..514].ends_with(&[0x90, 0x00]));

    assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
    server.join().expect("mock server thread");
    let _ = std::fs::remove_file(&sock_path);
}

#[test]
fn reconnects_cleanly_across_daemon_restart() {
    let sock_path = unique_socket_path("reconnect");
    let lun: Dword = 0x0002_0000;
    let dev = CString::new(sock_path.to_str().expect("utf8 path")).expect("CString");

    // Channel creation succeeds even when daemon socket does not exist yet.
    assert_eq!(
        unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
        IFD_SUCCESS
    );
    assert_eq!(IFDHICCPresence(lun), IFD_ICC_NOT_PRESENT);

    // Start daemon instance #1.
    let present = Arc::new(AtomicBool::new(true));
    let server1 = spawn_mock_server(&sock_path, 1, Arc::clone(&present));
    assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);

    assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
    server1.join().expect("server1");
    let _ = std::fs::remove_file(&sock_path);

    // Re-open channel, connect to a server that drops the connection after one presence check.
    assert_eq!(
        unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
        IFD_SUCCESS
    );
    let listener = UnixListener::bind(&sock_path).expect("bind one-shot");
    let one_shot = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let req = read_request(&mut stream).expect("read").expect("req");
        assert_eq!(req, Request::Presence);
        write_response(&mut stream, &Response::Presence(true)).expect("write");
        // Drop stream + listener to simulate daemon stop.
    });
    assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);
    one_shot.join().expect("one_shot");

    // Next presence poll detects the broken connection and reports absence.
    assert_eq!(IFDHICCPresence(lun), IFD_ICC_NOT_PRESENT);

    // Start daemon instance #2 on the same socket path.
    let server2 = spawn_mock_server(&sock_path, 1, Arc::clone(&present));

    // Next presence poll reconnects automatically and reports present.
    assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);

    let mut atr = [0u8; MAX_ATR_SIZE];
    let mut atr_len: Dword = 0;
    assert_eq!(
        unsafe { IFDHPowerICC(lun, IFD_POWER_UP, atr.as_mut_ptr(), &raw mut atr_len) },
        IFD_SUCCESS
    );
    assert_eq!(&atr[..usize::try_from(atr_len).unwrap()], MOCK_ATR);

    assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
    server2.join().expect("server2");
    let _ = std::fs::remove_file(&sock_path);
}
