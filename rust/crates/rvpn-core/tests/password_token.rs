//! 密码令牌算法的回归测试。
//!
//! 六组样本全部来自真实抓包（官方客户端），逐字节比对。
//! 其中一组是中文密码，用来锁死「长度按 UTF-16 码元算」这一点。

use rvpn_core::commands::{password_token, token_to_password};

/// (密码, 令牌 hex)
const SAMPLES: &[(&str, &str)] = &[
    (
        "123456",
        "7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874",
    ),
    (
        "Aa022033",
        "4fca0aa935436abb397116db166b857b3c6c0eca6ba9054358bb0b7126db256bb67b3c6c",
    ),
    (
        "deepseektester",
        "cd157e9047733e8b5e4bf75fab3e5bd4984e4e57d97b0874c7e1f941ab37a9151b902273\
         4e8b2d4b925fce3e30d4ec4e2b57aa7b7c74a2e18b41ab37",
    ),
    (
        "123456",
        "8b3787dee468438689f68a59dc84ba37b5ded7687786bcf6bc59dc84",
    ),
    (
        "deepseektester",
        "cb27da578b2cda52a2c2929ffcba1bc4ce069a97ba1bfbc4bf9f51225fce\
         af27bf57ee2caa52d1c2f79f99ba70c4ba06ff97c91b8fc4da9f23225fce",
    ),
    // 中文密码：发 = U+53D1，UTF-16LE = d1 53
    (
        "发发发发发发",
        "a8973035e8dab8b6778b09a9eb2979c4e166398969e5a6d8d8faeb29",
    ),
];

fn hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
        .collect()
}

/// 密码按 UTF-16 码元数计算长度（不是 UTF-8 字节数）。
fn units(pw: &str) -> usize {
    pw.encode_utf16().count()
}

/// 密码转成 UTF-16LE 字节，并补齐到 (n+1) 个 u16。
fn padded_utf16le(pw: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in pw.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.resize(2 * (units(pw) + 1), 0);
    out
}

#[test]
fn token_has_expected_length() {
    for (pw, _) in SAMPLES {
        let tok = password_token(pw);
        assert_eq!(
            tok.len(),
            4 * (units(pw) + 1),
            "{pw:?} 的长度应为 4*(字符数+1)"
        );
    }
}

#[test]
fn token_is_two_halves_xor_and_random() {
    for (pw, _) in SAMPLES {
        let tok = password_token(pw);
        let half = tok.len() / 2;
        let pad = padded_utf16le(pw);

        for i in 0..half {
            assert_eq!(
                tok[i] ^ tok[half + i],
                pad[i],
                "{pw:?} 第 {i} 字节的异或结果不对"
            );
        }
    }
}

#[test]
fn password_is_recoverable_from_token() {
    for (pw, hexs) in SAMPLES {
        let tok = hex(hexs);
        assert_eq!(&token_to_password(&tok), pw, "从令牌反推密码失败");
    }
}

#[test]
fn regenerating_with_the_same_random_gives_the_same_token() {
    for (pw, hexs) in SAMPLES {
        let tok = hex(hexs);
        let half = tok.len() / 2;
        let rnd = &tok[half..];
        let pad = padded_utf16le(pw);

        assert_eq!(rnd.len(), pad.len(), "{pw:?} 随机段长度不对");

        let mut gen = Vec::with_capacity(tok.len());
        for i in 0..half {
            gen.push(rnd[i] ^ pad[i]);
        }
        gen.extend_from_slice(rnd);

        assert_eq!(gen, tok, "{pw:?} 重新生成后不一致");
    }
}

#[test]
fn ascii_password_only_touches_even_bytes() {
    // ASCII 的 UTF-16LE 是 (字符, 0x00)，所以只有偶数下标被异或 ——
    // 这就是早先误以为「只异或 u16 高字节」的原因。
    let tok = password_token("123456");
    let half = tok.len() / 2;
    for i in 0..half {
        let x = tok[i] ^ tok[half + i];
        if i % 2 == 0 && i < 12 {
            assert_eq!(x, b'1' + (i / 2) as u8, "第 {i} 字节");
        } else {
            assert_eq!(x, 0, "第 {i} 字节应为 0");
        }
    }
}
