const MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;

pub struct Member {
    #[allow(dead_code)]
    pub name: String,
    pub data: Vec<u8>,
}

pub fn is_archive(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

pub fn parse_members(data: &[u8]) -> Result<Vec<Member>, String> {
    if !is_archive(data) {
        return Err("not an archive".to_string());
    }
    let mut members = Vec::new();
    let mut long_names: &[u8] = &[];
    let mut off = MAGIC.len();
    while off < data.len() {
        let header = data
            .get(off..off + HEADER_LEN)
            .ok_or("truncated archive member header")?;
        if &header[58..60] != b"`\n" {
            return Err(format!("bad archive member header at offset {off}"));
        }
        let raw_name = std::str::from_utf8(&header[..16])
            .map_err(|_| "non-UTF-8 archive member name")?
            .trim_end_matches(' ');
        let size: usize = std::str::from_utf8(&header[48..58])
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or("bad archive member size")?;
        off += HEADER_LEN;
        let payload = data
            .get(off..off + size)
            .ok_or("truncated archive member")?;
        off += size + (size & 1);

        match raw_name {
            "//" => {
                long_names = payload;
                continue;
            }
            "/" => continue,
            _ => {}
        }

        let (name, body) = if let Some(len) = raw_name.strip_prefix("#1/") {
            let len: usize = len.parse().map_err(|_| "bad BSD archive name length")?;
            let name_bytes = payload.get(..len).ok_or("truncated BSD archive name")?;
            (
                String::from_utf8_lossy(name_bytes).into_owned(),
                &payload[len..],
            )
        } else if let Some(index) = raw_name.strip_prefix('/') {
            let index: usize = index.parse().map_err(|_| "bad GNU archive name index")?;
            let table = long_names.get(index..).unwrap_or(&[]);
            let end = table
                .windows(2)
                .position(|w| w == b"/\n")
                .unwrap_or(table.len());
            (String::from_utf8_lossy(&table[..end]).into_owned(), payload)
        } else {
            (raw_name.trim_end_matches('/').to_string(), payload)
        };

        members.push(Member {
            name,
            data: body.to_vec(),
        });
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name_field: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name_field,
            0,
            0,
            0,
            644,
            payload.len()
        )
        .into_bytes();
        out.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn parses_gnu_long_names_and_skips_index_members() {
        let mut ar = MAGIC.to_vec();
        ar.extend(member("/", b"\0\0\0\0"));
        ar.extend(member("//", b"a_very_long_member.o/\n"));
        ar.extend(member("/0", b"first"));
        ar.extend(member("short.o/", b"second!"));
        let members = parse_members(&ar).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["a_very_long_member.o", "short.o"]);
        assert_eq!(members[0].data, b"first");
        assert_eq!(members[1].data, b"second!");
    }

    #[test]
    fn rejects_bad_member_magic() {
        let mut ar = MAGIC.to_vec();
        ar.extend_from_slice(&[b' '; 60]);
        assert!(parse_members(&ar).is_err());
    }
}
