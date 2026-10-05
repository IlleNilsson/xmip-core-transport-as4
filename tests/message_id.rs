//! A keyed send carries its deduplication key as the User Message's
//! `eb:MessageId`, `key@xmip`, the same on every attempt of one Journey:
//! the receiving MSH receipts the repeat again and does not deliver it
//! again. An unkeyed send carries an id of its own.

use std::thread;

use transport::Transport;
use xmip_core_transport_as4::As4Transport;

/// A Journey's identifier, as the runtime hands it.
const KEY: &str = "0b6f5a52-7c1e-4d0a-9a4e-3f1d2c8b9e70";

#[test]
fn a_keyed_message_carries_the_journey_id_as_its_message_id_and_is_delivered_once() {
    let far_end = As4Transport::new("as4://127.0.0.1:0/msh", "Seller", "Buyer");
    let (listener, address) = far_end.bind().expect("bound");
    let taking = thread::spawn(move || {
        (0..3)
            .map(|_| {
                far_end
                    .accept_one(&listener)
                    .expect("receipted")
                    .map(|(message, taken)| (message.message_id, taken.bytes))
            })
            .collect::<Vec<_>>()
    });
    let near = As4Transport::new(format!("as4://{address}/msh"), "Buyer", "Seller");
    near.send_keyed("", b"order", KEY)
        .expect("sent, its Receipt verified");
    near.send_keyed("", b"order", KEY)
        .expect("sent again, receipted again");
    near.send("", b"order").expect("sent unkeyed");
    let taken = taking.join().expect("far end");
    let keyed = format!("{KEY}@xmip");
    assert_eq!(taken[0], Some((keyed.clone(), b"order".to_vec())));
    assert_eq!(
        taken[1], None,
        "the repeat is receipted, not delivered again"
    );
    let (other, _) = taken[2].clone().expect("an unkeyed message is delivered");
    assert_ne!(other, keyed);
}
