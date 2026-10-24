use rvpn_core::{Frame, RecordType, SnapshotState};
fn frame(tag: u32, inner: Frame) -> Vec<u8> {
    let mut f = Frame::new();
    f.container(tag, &inner.into_bytes());
    f.into_bytes()
}
#[test]
fn joins_identity_addresses_and_membership_without_confusing_network_type() {
    let mut me = Frame::new();
    me.node_id(42)
        .text(4, "本机")
        .u32(5, 0x1a000001)
        .u32_alt(0x11, 1)
        .u32(0x12, 4);
    let mut profile = Frame::new();
    profile
        .node_id(42)
        .text(4, "设备")
        .u32(5, 0x1a000001)
        .blob(
            5,
            RecordType::Address,
            &[0xfd, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a, 0, 0, 1],
        )
        .u32(0x21, 1)
        .u32(0x26, 3)
        .u32(0x3e, 17)
        .text(0xed, "2.1.1");
    let mut member = Frame::new();
    member.node_id(42).u32(10, 2);
    let mut net = Frame::new();
    net.guid(9, &[1; 16])
        .text(6, "测试网络")
        .u32(10, 1)
        .u32(0xa3, 5)
        .container(0x1324, &member.into_bytes());
    let mut collection = Frame::new();
    collection
        .container(0x1322, &profile.into_bytes())
        .container(0x1323, &net.into_bytes());
    me.container(0x1321, &collection.into_bytes());
    let state = SnapshotState::parse(&frame(0x1320, me));
    assert_eq!(state.power, Some(true));
    assert_eq!(state.service_state, Some(4));
    let net = &state.networks[0];
    assert_eq!(net.network_type, Some(1));
    assert_eq!(net.role, Some(2));
    assert!(net.can_manage());
    assert_eq!(net.enabled, Some(true));
    assert_eq!(net.block_new_members, Some(false));
    assert_eq!(net.allow_passwordless, Some(true));
    let peer = &net.members[0];
    assert_eq!(peer.virtual_ip.as_deref(), Some("26.0.0.1"));
    assert_eq!(peer.virtual_ipv6.as_deref(), Some("fdfd::1a00:1"));
    assert_eq!(peer.role, Some(2));
    assert_eq!(peer.online(), Some(true));
    assert_eq!(peer.latency_ms, Some(17));
}
#[test]
fn unknown_states_and_invalid_addresses_are_not_fabricated() {
    let mut m = Frame::new();
    m.node_id(55).text(4, "999.999.999.999");
    let state = SnapshotState::parse(&frame(0x1320, m));
    assert!(state.me.unwrap().virtual_ip.is_none());
    assert!(state.power.is_none());
    let peer = rvpn_core::MemberInfo {
        connection_status: Some(99),
        ..Default::default()
    };
    assert_eq!(peer.online(), None);
}
#[test]
fn deeply_nested_input_is_bounded() {
    let mut bytes = Vec::new();
    for _ in 0..100 {
        let mut f = Frame::new();
        f.container(0x1321, &bytes);
        bytes = f.into_bytes();
    }
    assert!(SnapshotState::parse(&bytes).networks.is_empty());
}
