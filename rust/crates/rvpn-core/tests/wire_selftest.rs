//! 自检：拿抓包得到的**真实字节**逐字节比对，确保编码与线上完全一致。
//!
//! 期望值全部来自 `docs/PROTOCOL_COMMANDS.md` 里记录的实际报文。

use rvpn_core::{encode_string, decode_string, Commands, RecordType, Wire, CommandCode};

fn hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
        .collect()
}

fn check(name: &str, actual: Vec<u8>, expected: &str) {
    let want = hex(expected);
    assert_eq!(
        actual, want,
        "\n{name} 不一致\n实际: {}\n期望: {}",
        actual.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        want.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("  ✓ {name:<28} {} 字节", actual.len());
}

#[test]
fn frames_match_captured_bytes() {
    println!("\n=== 命令帧与抓包逐字节比对 ===");

    // 1. 加入网络：reqId=0x17，名字 "Minecraft [Português 10]"，实测 102 字节
    check(
        "加入网络 join",
        Commands::join_network("Minecraft [Português 10]", 0x17),
        "00000004 0100 034a 00000017
         00000004 0100 0300 00000003
         00000046 0000131b
         00000004 0b00 033f 00000001
         00000032 0300 0306
         004d0069006e0065006300720061006600740020005b0050006f0072007400750067007500ea0073002000310030005d
         0001",
    );

    // 2. 改别名：reqId=0x1a，别名 "快乐狐狸1"，实测 44 字节
    check(
        "改别名 alias",
        Commands::change_alias("快乐狐狸1", 0x1a),
        "00000004 0100 034a 0000001a
         00000004 0100 0300 00000012
         0000000c 0300 0304
         5feb4e5072d072f800310001",
    );

    // 3. VPN 总开关：reqId=0x2f，关闭，实测 36 字节
    check(
        "总开关 power off",
        Commands::switch_power(false, 0x2f),
        "00000004 0100 034a 0000002f
         00000004 0100 0300 00000004
         00000004 0b00 0311 00000000",
    );

    // 4. 总开关开启
    check(
        "总开关 power on",
        Commands::switch_power(true, 0x30),
        "00000004 0100 034a 00000030
         00000004 0100 0300 00000004
         00000004 0b00 0311 00000001",
    );

    // 5. 启用网络：GUID + 字段 0x16=1，实测 60 字节
    let guid = hex("89c588a86f14437aab52fd112f18efba");
    check(
        "启用网络 enable",
        Commands::set_network_enabled(&guid, true, 0x30),
        "00000004 0100 034a 00000030
         00000004 0100 0300 00000008
         00000010 0d00 0309 89c588a86f14437aab52fd112f18efba
         00000004 0b00 0316 00000001",
    );

    // 6. 删除网络：实测 48 字节
    check(
        "删除网络 delete",
        Commands::delete_network(&guid, 0x33),
        "00000004 0100 034a 00000033
         00000004 0100 0300 0000000f
         00000010 0d00 0309 89c588a86f14437aab52fd112f18efba",
    );

    // 7. 离开网络
    check(
        "离开网络 leave",
        Commands::leave_network(&guid, 0x23),
        "00000004 0100 034a 00000023
         00000004 0100 0300 00000005
         00000010 0d00 0309 89c588a86f14437aab52fd112f18efba",
    );
}

#[test]
fn string_roundtrip() {
    for s in ["abc", "快乐狐狸", "Minecraft [Português 10]", "a"] {
        let enc = encode_string(s);
        let dec = decode_string(&enc);
        assert_eq!(dec.as_deref(), Some(s), "往返失败: {s}");
        println!("  ✓ 往返 {s:<30} {}", enc.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
}

#[test]
fn parse_own_join_frame() {
    let frame = Commands::join_network("Minecraft [Português 10]", 0x17);
    let recs = Wire::parse(&frame);
    assert_eq!(recs.len(), 3, "顶层应有 3 条记录");

    assert_eq!(Wire::request_id(&frame), 0x17);

    // 容器里的网络名
    let name = recs
        .iter()
        .filter_map(|r| r.children.as_ref())
        .flatten()
        .find(|c| c.field == 0x06 && c.ty == RecordType::Str as u8)
        .and_then(|c| c.as_string());
    assert_eq!(name.as_deref(), Some("Minecraft [Português 10]"));
    println!("  ✓ 解析回读：请求编号 0x17，网络名 {name:?}");
}

#[test]
fn command_codes_are_right() {
    assert_eq!(CommandCode::SwitchPower as u32, 0x04);
    assert_eq!(CommandCode::KickNode as u32, 0x06);
    assert_eq!(CommandCode::EnumPublicNetworks as u32, 0x13);
}
