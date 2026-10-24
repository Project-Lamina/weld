use crate::collections::HashMap;

use std::io::{Read, Seek, SeekFrom};

const MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;

pub struct Member {
    #[allow(dead_code)]
    pub name: String,
    /// Body range within the archive buffer; members are not copied out.
    pub start: usize,
    pub len: usize,
    pub offset: usize,
}

impl Member {
    pub fn data<'a>(&self, archive: &'a [u8]) -> &'a [u8] {
        archive.get(self.start..self.start + self.len).unwrap_or(&[])
    }
}

pub struct Archive {
    pub members: Vec<Member>,
    pub index: Option<HashMap<String, Vec<usize>>>,
}

pub struct HeaderScan {
    pub members: Vec<Member>,
    pub index: Option<HashMap<String, Vec<usize>>>,
}

fn read_range<R: Read + Seek>(reader: &mut R, off: u64, buf: &mut [u8]) -> Result<(), String> {
    reader
        .seek(SeekFrom::Start(off))
        .and_then(|_| reader.read_exact(buf))
        .map_err(|e| format!("read failed: {e}"))
}

/// Reads member headers and the symbol index of an archive without reading member bodies.
/// Fails on the same malformed input that `parse_members` rejects.
pub fn scan_headers<R: Read + Seek>(reader: &mut R, len: u64) -> Result<HeaderScan, String> {
    let mut magic = [0u8; 8];
    read_range(reader, 0, &mut magic)?;
    if &magic != MAGIC {
        return Err("not an archive".to_string());
    }
    let mut members = Vec::new();
    let mut index = None;
    let mut off = MAGIC.len() as u64;
    let mut header = [0u8; HEADER_LEN];
    while off < len {
        read_range(reader, off, &mut header)?;
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
        let payload_at = off + HEADER_LEN as u64;
        let end = payload_at + size as u64;
        if end > len {
            return Err("truncated archive member".to_string());
        }
        let next = end + (size as u64 & 1);
        match raw_name {
            "//" => {}
            "/" => {
                let mut payload = vec![0u8; size];
                read_range(reader, payload_at, &mut payload)?;
                index = parse_index(&payload);
            }
            _ => {
                let (start, body_len) = if let Some(name_len) = raw_name.strip_prefix("#1/") {
                    let name_len: usize = name_len
                        .parse()
                        .map_err(|_| "bad BSD archive name length")?;
                    if name_len > size {
                        return Err("truncated BSD archive name".to_string());
                    }
                    (payload_at + name_len as u64, size - name_len)
                } else {
                    if let Some(index) = raw_name.strip_prefix('/') {
                        index
                            .parse::<usize>()
                            .map_err(|_| "bad GNU archive name index")?;
                    }
                    (payload_at, size)
                };
                members.push(Member {
                    name: String::new(),
                    start: start as usize,
                    len: body_len,
                    offset: off as usize,
                });
            }
        }
        off = next;
    }
    Ok(HeaderScan { members, index })
}

fn parse_index(data: &[u8]) -> Option<HashMap<String, Vec<usize>>> {
    let count = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
    let names_start = 4usize.checked_add(count.checked_mul(4)?)?;
    let offsets = data.get(4..names_start)?;
    let mut names = data.get(names_start..)?;
    let mut index: HashMap<String, Vec<usize>> = HashMap::default();
    for offset in offsets.as_chunks::<4>().0 {
        let end = names.iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&names[..end]).ok()?.to_string();
        let offset = u32::from_be_bytes(*offset) as usize;
        index.entry(name).or_default().push(offset);
        names = &names[end + 1..];
    }
    Some(index)
}

pub fn is_archive(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

pub fn parse_members(data: &[u8]) -> Result<Archive, String> {
    if !is_archive(data) {
        return Err("not an archive".to_string());
    }
    let mut members = Vec::new();
    let mut index = None;
    let mut long_names: &[u8] = &[];
    let mut off = MAGIC.len();
    while off < data.len() {
        let offset = off;
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
            "/" => {
                index = parse_index(payload);
                continue;
            }
            _ => {}
        }

        let body_at = off - size - (size & 1);
        let (name, body_start, body_len) = if let Some(len) = raw_name.strip_prefix("#1/") {
            let len: usize = len.parse().map_err(|_| "bad BSD archive name length")?;
            let name_bytes = payload.get(..len).ok_or("truncated BSD archive name")?;
            (
                String::from_utf8_lossy(name_bytes).into_owned(),
                body_at + len,
                size - len,
            )
        } else if let Some(index) = raw_name.strip_prefix('/') {
            let index: usize = index.parse().map_err(|_| "bad GNU archive name index")?;
            let table = long_names.get(index..).unwrap_or(&[]);
            let end = table
                .windows(2)
                .position(|w| w == b"/\n")
                .unwrap_or(table.len());
            (
                String::from_utf8_lossy(&table[..end]).into_owned(),
                body_at,
                size,
            )
        } else {
            (raw_name.trim_end_matches('/').to_string(), body_at, size)
        };

        members.push(Member {
            name,
            start: body_start,
            len: body_len,
            offset,
        });
    }
    Ok(Archive { members, index })
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
    fn parses_gnu_long_names_and_index() {
        let mut ar = MAGIC.to_vec();
        ar.extend(member("/", b"\0\0\0\0"));
        ar.extend(member("//", b"a_very_long_member.o/\n"));
        ar.extend(member("/0", b"first"));
        ar.extend(member("short.o/", b"second!"));
        let archive = parse_members(&ar).unwrap();
        assert!(archive.index.unwrap().is_empty());
        let members = archive.members;
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["a_very_long_member.o", "short.o"]);
        assert_eq!(members[0].data(&ar), b"first");
        assert_eq!(members[1].data(&ar), b"second!");
    }

    #[test]
    fn header_scan_matches_full_parse() {
        let mut ar = MAGIC.to_vec();
        ar.extend(member("/", b"\0\0\0\0"));
        ar.extend(member("//", b"a_very_long_member.o/\n"));
        ar.extend(member("/0", b"first"));
        ar.extend(member("#1/4", b"abcdbody"));
        ar.extend(member("short.o/", b"second!"));
        let full = parse_members(&ar).unwrap();
        let scan = scan_headers(&mut std::io::Cursor::new(&ar), ar.len() as u64).unwrap();
        let spans = |members: &[Member]| -> Vec<(usize, usize, usize)> {
            members.iter().map(|m| (m.offset, m.start, m.len)).collect()
        };
        assert_eq!(spans(&scan.members), spans(&full.members));
        assert_eq!(scan.index.is_some(), full.index.is_some());
    }

    #[test]
    fn parses_duplicate_index_names_and_member_offsets() {
        let mut payload = 3u32.to_be_bytes().to_vec();
        for offset in [200u32, 100, 200] {
            payload.extend(offset.to_be_bytes());
        }
        payload.extend(b"foo\0foo\0bar\0");
        let mut ar = MAGIC.to_vec();
        ar.extend(member("/", &payload));
        let offset = ar.len();
        ar.extend(member("x.o/", b"object"));
        let archive = parse_members(&ar).unwrap();
        let index = archive.index.unwrap();
        assert_eq!(index["foo"], [200, 100]);
        assert_eq!(index["bar"], [200]);
        assert_eq!(archive.members[0].offset, offset);
    }

    #[test]
    fn malformed_index_falls_back() {
        for payload in [
            b"".as_slice(),
            &[0, 0, 0, 1],
            &[0, 0, 0, 1, 0, 0, 0, 68, b'x'],
        ] {
            let mut ar = MAGIC.to_vec();
            ar.extend(member("/", payload));
            assert!(parse_members(&ar).unwrap().index.is_none());
        }
    }

    #[test]
    fn rejects_bad_member_magic() {
        let mut ar = MAGIC.to_vec();
        ar.extend_from_slice(&[b' '; 60]);
        assert!(parse_members(&ar).is_err());
    }
}
