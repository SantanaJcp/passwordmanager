// SPDX-License-Identifier: AGPL-3.0-only

use pm_crypto::Pmf1Vector;

#[test]
fn pmf1_frames_chunks_with_final_even_for_empty_files() {
    for plaintext in [Vec::new(), vec![0x41; 1_048_577]] {
        let vector = Pmf1Vector::seal([1; 16], [2; 16], [3; 16], &plaintext).unwrap();
        assert_eq!(&vector.bytes()[..4], b"PMF1");
        assert_eq!(vector.open().unwrap(), plaintext);
    }
}

#[test]
fn pmf1_rejects_tampering_truncation_trailing_data_and_reordered_chunks() {
    let vector = Pmf1Vector::seal([4; 16], [5; 16], [6; 16], &vec![0x5a; 1_048_577]).unwrap();
    let bytes = vector.bytes();

    let mut tampered = bytes.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(vector.open_bytes(&tampered).is_err());
    assert!(vector.open_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(vector.open_bytes(&trailing).is_err());

    let mut reordered = bytes.to_vec();
    swap_first_two_frames(&mut reordered);
    assert!(vector.open_bytes(&reordered).is_err());
}

fn swap_first_two_frames(bytes: &mut Vec<u8>) {
    let header_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let first = 8 + header_len;
    let first_len = u32::from_be_bytes(bytes[first..first + 4].try_into().unwrap()) as usize;
    let second = first + 4 + first_len;
    let second_len = u32::from_be_bytes(bytes[second..second + 4].try_into().unwrap()) as usize;
    let frame_one = bytes[first..second].to_vec();
    let frame_two = bytes[second..second + 4 + second_len].to_vec();
    bytes.splice(
        first..second + 4 + second_len,
        frame_two.into_iter().chain(frame_one),
    );
}
