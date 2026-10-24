//! 密码令牌算法的回归测试。
//!
//! 五组样本全部来自真实抓包（官方客户端），逐字节比对。

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
];

fn hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn token_has_expected_length() {
    for (pw, _) in SAMPLES {
        let tok = password_token(pw);
        assert_eq!(
            tok.len(),
            4 * (pw.len() + 1),
            "{pw:?} 的长度应为 4*(n+1)"
        );
    }
}

#[test]
fn token_second_half_is_the_random_part() {
    let tok = password_token("123456");
    let half = 6 + 1;
    // 后半段原样出现在令牌里；前半段与之共享低字节
    for i in 0..half {
        let a_lo = tok[i * 2 + 1];
        let b_lo = tok[(half + i) * 2 + 1];
        assert_eq!(a_lo, b_lo, "第 {i} 个 u16 的低字节应相同");
    }
    // 最后一位没有对应字符，两半应完全一致
    assert_eq!(tok[(half - 1) * 2], tok[(half + half - 1) * 2]);
    assert_eq!(tok[(half - 1) * 2 + 1], tok[(half + half - 1) * 2 + 1]);
}

#[test]
fn password_is_recoverable_from_token() {
    for (pw, hexs) in SAMPLES {
        let tok = hex(hexs);
        let got = token_to_password(&tok);
        assert_eq!(&got, pw, "从令牌反推密码失败");
    }
}

#[test]
fn regenerating_with_the_same_random_gives_the_same_token() {
    // 用令牌后半段的随机数重新构造，必须和原令牌逐字节一致
    for (pw, hexs) in SAMPLES {
        let tok = hex(hexs);
        let n = pw.len();
        let half = n + 1;
        let rnd = &tok[half * 2..];

        let mut gen = Vec::with_capacity(4 * half);
        for i in 0..half {
            let hi = rnd[i * 2];
            let lo = rnd[i * 2 + 1];
            let ch = if i < n { pw.as_bytes()[i] } else { 0 };
            gen.push(hi ^ ch);
            gen.push(lo);
        }
        gen.extend_from_slice(rnd);

        assert_eq!(gen, tok, "{pw:?} 重新生成后不一致");
    }
}
