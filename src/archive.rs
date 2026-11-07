use crate::collections::HashMap;
use crate::object;

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

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
        archive
            .get(self.start..self.start + self.len)
            .unwrap_or(&[])
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
                    let mut name_bytes = vec![0u8; name_len];
                    read_range(reader, payload_at, &mut name_bytes)?;
                    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
                    if is_bsd_symbol_table(&String::from_utf8_lossy(&name_bytes[..end])) {
                        off = next;
                        continue;
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

/// A BSD archive carries its symbol index as a member named `__.SYMDEF`, or
/// `__.SYMDEF SORTED` when `ranlib` sorted it, reached through the `#1/` extended
/// name. It is the index, not an object, and must not be handed back as a member.
fn is_bsd_symbol_table(name: &str) -> bool {
    matches!(name, "__.SYMDEF" | "__.SYMDEF SORTED")
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
            let name_bytes = name_bytes.split(|&b| b == 0).next().unwrap_or(name_bytes);
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

        if is_bsd_symbol_table(&name) {
            continue;
        }

        members.push(Member {
            name,
            start: body_start,
            len: body_len,
            offset,
        });
    }
    Ok(Archive { members, index })
}

pub struct NewMember<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
    pub symbols: &'a [String],
}

const NAME_FIELD_LEN: usize = 16;
const MAX_MEMBER_SIZE: usize = 9_999_999_999;

fn check_member_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty member name".to_string());
    }
    if name.ends_with(' ') {
        return Err(
            "member name ends with a space, which an archive header cannot keep".to_string(),
        );
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'/') {
        return Err(
            "member name contains a control character or '/', which cannot be stored".to_string(),
        );
    }
    Ok(())
}

fn padded(len: usize) -> usize {
    len + (len & 1)
}

fn push_header(out: &mut Vec<u8>, name_field: &str, size: usize) {
    out.extend_from_slice(
        format!(
            "{name_field:<16}{:<12}{:<6}{:<6}{:<8}{size:<10}`\n",
            0, 0, 0, 644
        )
        .as_bytes(),
    );
}

/// Writes a GNU-flavour archive: a `/` symbol index, a `//` long-name table, then the members.
/// Every header has zeroed mtime, uid and gid, so the same inputs give the same bytes.
pub fn write_archive(members: &[NewMember]) -> Result<Vec<u8>, String> {
    let mut long_names = Vec::new();
    let mut name_fields = Vec::with_capacity(members.len());
    let mut symbol_count = 0usize;
    let mut symbol_bytes = 0usize;
    for member in members {
        check_member_name(member.name).map_err(|e| format!("{}: {e}", member.name))?;
        if member.data.len() > MAX_MEMBER_SIZE {
            return Err(format!(
                "{}: member is too large for an archive header",
                member.name
            ));
        }
        if member.name.len() < NAME_FIELD_LEN {
            name_fields.push(format!("{}/", member.name));
        } else {
            name_fields.push(format!("/{}", long_names.len()));
            long_names.extend_from_slice(member.name.as_bytes());
            long_names.extend_from_slice(b"/\n");
        }
        for symbol in member.symbols {
            if symbol.is_empty() || symbol.contains('\0') {
                return Err(format!(
                    "{}: symbol name {symbol:?} cannot be indexed",
                    member.name
                ));
            }
            symbol_count += 1;
            symbol_bytes += symbol.len() + 1;
        }
    }
    let index_len = 4 + 4 * symbol_count + symbol_bytes;
    if index_len > MAX_MEMBER_SIZE {
        return Err("symbol index is too large for an archive header".to_string());
    }
    let mut offset = MAGIC.len() + HEADER_LEN + padded(index_len);
    if !long_names.is_empty() {
        offset += HEADER_LEN + padded(long_names.len());
    }
    let mut member_offsets = Vec::with_capacity(members.len());
    for member in members {
        member_offsets.push(offset);
        offset += HEADER_LEN + padded(member.data.len());
    }
    if offset > u32::MAX as usize {
        return Err("archive is larger than the 32-bit symbol index can address".to_string());
    }

    let mut index = Vec::with_capacity(index_len);
    index.extend_from_slice(&(symbol_count as u32).to_be_bytes());
    for (member, at) in members.iter().zip(&member_offsets) {
        for _ in member.symbols {
            index.extend_from_slice(&(*at as u32).to_be_bytes());
        }
    }
    for member in members {
        for symbol in member.symbols {
            index.extend_from_slice(symbol.as_bytes());
            index.push(0);
        }
    }

    let mut out = Vec::with_capacity(offset);
    out.extend_from_slice(MAGIC);
    push_header(&mut out, "/", index.len());
    out.extend_from_slice(&index);
    if index.len() & 1 == 1 {
        out.push(b'\n');
    }
    if !long_names.is_empty() {
        push_header(&mut out, "//", long_names.len());
        out.extend_from_slice(&long_names);
        if long_names.len() & 1 == 1 {
            out.push(b'\n');
        }
    }
    for (member, name_field) in members.iter().zip(&name_fields) {
        push_header(&mut out, name_field, member.data.len());
        out.extend_from_slice(member.data);
        if member.data.len() & 1 == 1 {
            out.push(b'\n');
        }
    }
    debug_assert_eq!(out.len(), offset);
    Ok(out)
}

/// Archives relocatable objects into `output`, naming each member after its file name.
pub fn create_archive(output: &Path, inputs: &[PathBuf]) -> Result<(), String> {
    let mut loaded = Vec::with_capacity(inputs.len());
    for path in inputs {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{}: file name is not valid UTF-8", path.display()))?
            .to_string();
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        object::reject_lto_objects(std::slice::from_ref(&data))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let symbols =
            object::object_symbols(&data).map_err(|e| format!("{}: {e}", path.display()))?;
        loaded.push((name, data, symbols));
    }
    let members: Vec<NewMember> = loaded
        .iter()
        .map(|(name, data, symbols)| NewMember {
            name,
            data,
            symbols,
        })
        .collect();
    let macho = loaded
        .iter()
        .filter(|(_, data, _)| crate::macho::is_macho64(data))
        .count();
    let archive = match macho {
        0 => write_archive(&members)?,
        n if n == members.len() => write_archive_bsd(&members)?,
        _ => return Err("Mach-O objects cannot share an archive with other formats".into()),
    };
    std::fs::write(output, archive).map_err(|e| format!("{}: {e}", output.display()))
}

/// The symbol index a BSD archive leads with, sorted by name as `ranlib -s` leaves it.
const BSD_SYMDEF: &str = "__.SYMDEF SORTED";

/// `#1/` name length that pads `name` so the member body after it starts on an
/// eight-byte boundary, given a header that does.
fn bsd_name_len(name: &str) -> usize {
    (HEADER_LEN + name.len()).next_multiple_of(8) - HEADER_LEN
}

/// Size field of a BSD member: the padded name, the body, and the zero bytes that put
/// the next header on an eight-byte boundary. ld64 wants Mach-O members aligned.
fn bsd_member_size(name: &str, body: usize) -> usize {
    (HEADER_LEN + bsd_name_len(name) + body).next_multiple_of(8) - HEADER_LEN
}

fn push_bsd_member(out: &mut Vec<u8>, name: &str, body: &[u8]) {
    let name_len = bsd_name_len(name);
    let size = bsd_member_size(name, body.len());
    push_header(out, &format!("#1/{name_len}"), size);
    out.extend_from_slice(name.as_bytes());
    out.resize(out.len() + name_len - name.len(), 0);
    out.extend_from_slice(body);
    out.resize(out.len() + size - name_len - body.len(), 0);
}

/// Writes a BSD archive as Apple's `libtool -static` does: a `__.SYMDEF SORTED` index of
/// little-endian `ranlib` entries (name offset, member header offset) and a string
/// table, then each member under a `#1/` name. Headers have zeroed mtime, uid and gid.
pub fn write_archive_bsd(members: &[NewMember]) -> Result<Vec<u8>, String> {
    let mut entries: Vec<(&str, usize)> = Vec::new();
    for (index, member) in members.iter().enumerate() {
        check_member_name(member.name).map_err(|e| format!("{}: {e}", member.name))?;
        for symbol in member.symbols {
            if symbol.is_empty() || symbol.contains('\0') {
                return Err(format!(
                    "{}: symbol name {symbol:?} cannot be indexed",
                    member.name
                ));
            }
            entries.push((symbol, index));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut strings = Vec::new();
    let mut name_offsets = Vec::with_capacity(entries.len());
    for (symbol, _) in &entries {
        name_offsets.push(strings.len());
        strings.extend_from_slice(symbol.as_bytes());
        strings.push(0);
    }
    strings.resize(strings.len().next_multiple_of(8), 0);
    let table_len = 4 + 8 * entries.len() + 4 + strings.len();

    let mut offset = MAGIC.len() + HEADER_LEN + bsd_member_size(BSD_SYMDEF, table_len);
    let mut member_offsets = Vec::with_capacity(members.len());
    for member in members {
        member_offsets.push(offset);
        let size = bsd_member_size(member.name, member.data.len());
        if size > MAX_MEMBER_SIZE {
            return Err(format!(
                "{}: member is too large for an archive header",
                member.name
            ));
        }
        offset += HEADER_LEN + size;
    }
    if offset > u32::MAX as usize {
        return Err("archive is larger than the 32-bit symbol index can address".to_string());
    }

    let mut table = Vec::with_capacity(table_len);
    table.extend_from_slice(&((8 * entries.len()) as u32).to_le_bytes());
    for ((_, member), name_at) in entries.iter().zip(&name_offsets) {
        table.extend_from_slice(&(*name_at as u32).to_le_bytes());
        table.extend_from_slice(&(member_offsets[*member] as u32).to_le_bytes());
    }
    table.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    table.extend_from_slice(&strings);

    let mut out = Vec::with_capacity(offset);
    out.extend_from_slice(MAGIC);
    push_bsd_member(&mut out, BSD_SYMDEF, &table);
    for member in members {
        push_bsd_member(&mut out, member.name, member.data);
    }
    debug_assert_eq!(out.len(), offset);
    Ok(out)
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

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn written_archive_round_trips_through_reader() {
        let long = "a_member_with_a_name_longer_than_sixteen.o";
        let symbols_a = owned(&["alpha", "alpha_twice"]);
        let symbols_b = owned(&["beta"]);
        let symbols_c = owned(&[]);
        let ar = write_archive(&[
            NewMember {
                name: "a.o",
                data: b"object-a!",
                symbols: &symbols_a,
            },
            NewMember {
                name: long,
                data: b"object-b",
                symbols: &symbols_b,
            },
            NewMember {
                name: "c.o",
                data: b"c",
                symbols: &symbols_c,
            },
        ])
        .unwrap();

        let archive = parse_members(&ar).unwrap();
        let names: Vec<&str> = archive.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["a.o", long, "c.o"]);
        let bodies: Vec<&[u8]> = archive.members.iter().map(|m| m.data(&ar)).collect();
        assert_eq!(bodies, [&b"object-a!"[..], &b"object-b"[..], &b"c"[..]]);

        let scan = scan_headers(&mut std::io::Cursor::new(&ar), ar.len() as u64).unwrap();
        let spans = |members: &[Member]| -> Vec<(usize, usize, usize)> {
            members.iter().map(|m| (m.offset, m.start, m.len)).collect()
        };
        assert_eq!(spans(&scan.members), spans(&archive.members));
    }

    #[test]
    fn bsd_archive_aligns_members_and_sorts_its_index() {
        let long = "a_member_with_a_name_longer_than_sixteen.o";
        let symbols_a = owned(&["_zeta", "_alpha"]);
        let symbols_b = owned(&["_beta"]);
        let ar = write_archive_bsd(&[
            NewMember {
                name: "a.o",
                data: b"object-a!",
                symbols: &symbols_a,
            },
            NewMember {
                name: long,
                data: b"object-b",
                symbols: &symbols_b,
            },
        ])
        .unwrap();

        let archive = parse_members(&ar).unwrap();
        assert_eq!(archive.members.len(), 2);
        for (member, body) in archive.members.iter().zip([&b"object-a!"[..], b"object-b"]) {
            assert_eq!(member.offset % 8, 0);
            assert_eq!(member.start % 8, 0);
            assert!(member.data(&ar).starts_with(body));
        }

        // The index: ranlib array size, (name offset, header offset) pairs, string
        // table size, strings.
        let word = |at: usize| u32::from_le_bytes(ar[at..at + 4].try_into().unwrap()) as usize;
        let table = MAGIC.len() + HEADER_LEN + bsd_name_len(BSD_SYMDEF);
        assert_eq!(
            &ar[MAGIC.len() + HEADER_LEN..table - 4],
            BSD_SYMDEF.as_bytes()
        );
        let count = word(table) / 8;
        let strings = table + 4 + 8 * count + 4;
        let entries: Vec<(String, usize)> = (0..count)
            .map(|i| {
                let name_at = strings + word(table + 4 + 8 * i);
                let end = ar[name_at..].iter().position(|&b| b == 0).unwrap();
                let name = String::from_utf8(ar[name_at..name_at + end].to_vec()).unwrap();
                (name, word(table + 8 + 8 * i))
            })
            .collect();
        let (a, b) = (archive.members[0].offset, archive.members[1].offset);
        assert_eq!(
            entries,
            [
                ("_alpha".to_string(), a),
                ("_beta".to_string(), b),
                ("_zeta".to_string(), a)
            ]
        );
    }

    #[test]
    fn symbol_index_names_each_defining_member() {
        let symbols_a = owned(&["alpha", "alpha_twice"]);
        let symbols_b = owned(&["beta", "alpha_twice"]);
        let ar = write_archive(&[
            NewMember {
                name: "a.o",
                data: b"aa",
                symbols: &symbols_a,
            },
            NewMember {
                name: "b.o",
                data: b"bb",
                symbols: &symbols_b,
            },
        ])
        .unwrap();
        let archive = parse_members(&ar).unwrap();
        let index = archive.index.expect("index written");
        assert_eq!(index["alpha"], [archive.members[0].offset]);
        assert_eq!(index["beta"], [archive.members[1].offset]);
        assert_eq!(
            index["alpha_twice"],
            [archive.members[0].offset, archive.members[1].offset]
        );
        assert_eq!(index.len(), 3);
    }

    #[test]
    fn names_at_the_16_byte_boundary_survive_round_trip() {
        let fifteen = "fifteen_chars.o";
        let sixteen = "sixteen_chars.oo";
        assert_eq!((fifteen.len(), sixteen.len()), (15, 16));
        let none: Vec<String> = Vec::new();
        let ar = write_archive(&[
            NewMember {
                name: fifteen,
                data: b"1",
                symbols: &none,
            },
            NewMember {
                name: sixteen,
                data: b"2",
                symbols: &none,
            },
        ])
        .unwrap();
        let names: Vec<String> = parse_members(&ar)
            .unwrap()
            .members
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(names, [fifteen, sixteen]);
    }

    #[test]
    fn empty_archive_has_an_empty_index() {
        let ar = write_archive(&[]).unwrap();
        assert_eq!(ar.len(), MAGIC.len() + HEADER_LEN + 4);
        let archive = parse_members(&ar).unwrap();
        assert!(archive.members.is_empty());
        assert!(archive.index.expect("index written").is_empty());
        let scan = scan_headers(&mut std::io::Cursor::new(&ar), ar.len() as u64).unwrap();
        assert!(scan.members.is_empty());
        assert!(scan.index.is_some());
    }

    #[test]
    fn bsd_symbol_table_is_the_index_not_a_member() {
        // `ranlib` on Darwin names it `__.SYMDEF SORTED`, NUL-padded to the
        // `#1/` name length. Linking it as an object is a wrong answer.
        let mut ar = MAGIC.to_vec();
        let mut symdef = b"__.SYMDEF SORTED\0\0\0\0".to_vec();
        symdef.extend_from_slice(b"indexpayload");
        ar.extend(member("#1/20", &symdef));
        let mut obj = b"first.o\0".to_vec();
        obj.extend_from_slice(b"first body!");
        ar.extend(member("#1/8", &obj));

        let archive = parse_members(&ar).unwrap();
        let names: Vec<&str> = archive.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["first.o"]);
        assert_eq!(archive.members[0].data(&ar), b"first body!");

        let scan = scan_headers(&mut std::io::Cursor::new(&ar), ar.len() as u64).unwrap();
        assert_eq!(scan.members.len(), 1);
    }

    /// Every member header, for a failure message. The host `ar` decides the archive
    /// dialect, so a mismatch has to say what it actually wrote.
    fn walk(ar: &[u8]) -> String {
        let mut out = String::from("\narchive layout:");
        let mut off = MAGIC.len();
        while off + HEADER_LEN <= ar.len() {
            let header = &ar[off..off + HEADER_LEN];
            let raw = String::from_utf8_lossy(&header[..16])
                .trim_end()
                .to_string();
            let Ok(size) = String::from_utf8_lossy(&header[48..58])
                .trim()
                .parse::<usize>()
            else {
                out.push_str(&format!("\n  off={off} unparsable size"));
                break;
            };
            out.push_str(&format!("\n  off={off} name={raw:?} size={size}"));
            if let Some(len) = raw
                .strip_prefix("#1/")
                .and_then(|n| n.parse::<usize>().ok())
                && let Some(bytes) = ar.get(off + HEADER_LEN..off + HEADER_LEN + len)
            {
                out.push_str(&format!(" bsdname={:?}", String::from_utf8_lossy(bytes)));
            }
            off += HEADER_LEN + size + (size & 1);
        }
        out.push_str(&format!("\n  ended at {off}, len {}", ar.len()));
        out
    }

    /// The target `ras` should assemble for so the host `ar` accepts the member.
    fn host_target() -> (
        lamina_platform::TargetArchitecture,
        lamina_platform::TargetOperatingSystem,
    ) {
        use lamina_platform::{TargetArchitecture as A, TargetOperatingSystem as O};
        let arch = if cfg!(target_arch = "aarch64") {
            A::Aarch64
        } else {
            A::X86_64
        };
        let os = if cfg!(target_os = "macos") {
            O::MacOS
        } else if cfg!(target_os = "windows") {
            O::Windows
        } else {
            O::Linux
        };
        (arch, os)
    }

    #[test]
    fn system_ar_archive_parses_with_the_reader() {
        let guard = crate::test_support::TempDir::new("archive-ar");
        let dir = guard.path();
        // Real host objects, not byte blobs: Darwin's `ar` runs `ranlib` whatever
        // flags it is given, and silently drops a member it cannot index.
        let (arch, os) = host_target();
        for (name, sym) in [("first.o", "first"), ("a_longer_member_name.o", "second")] {
            let asm = format!(".text\n.globl {sym}\n{sym}:\n  ret\n");
            let mut assembler = ras::Ras::new(arch, os).expect("ras");
            assembler.assemble(&asm, &dir.join(name)).expect("assemble");
        }
        let status = std::process::Command::new("ar")
            .current_dir(dir)
            .args(["rcs", "lib.a", "first.o", "a_longer_member_name.o"])
            .status()
            .unwrap();
        assert!(status.success());
        let ar = std::fs::read(dir.join("lib.a")).unwrap();
        let archive = parse_members(&ar).unwrap();
        let names: Vec<&str> = archive.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            ["first.o", "a_longer_member_name.o"],
            "{}",
            walk(&ar)
        );
        // `ar` may pad a member's data; what it was given comes first.
        for member in &archive.members {
            let on_disk = std::fs::read(dir.join(&member.name)).unwrap();
            assert!(
                member.data(&ar).starts_with(&on_disk),
                "{} truncated",
                member.name
            );
        }
    }

    #[test]
    fn unrepresentable_members_are_refused_with_their_name() {
        let none: Vec<String> = Vec::new();
        for name in ["bad\nname.o", "trailing.o ", "slash/name.o", "nul\0.o", ""] {
            let result = write_archive(&[NewMember {
                name,
                data: b"x",
                symbols: &none,
            }]);
            assert!(result.is_err(), "{name:?} was accepted");
        }
        let err = write_archive(&[NewMember {
            name: "slash/name.o",
            data: b"x",
            symbols: &none,
        }])
        .unwrap_err();
        assert!(err.starts_with("slash/name.o: "), "{err}");

        let bad_symbols = owned(&["fine", ""]);
        let err = write_archive(&[NewMember {
            name: "empty_sym.o",
            data: b"x",
            symbols: &bad_symbols,
        }])
        .unwrap_err();
        assert!(err.starts_with("empty_sym.o: "), "{err}");
    }

    #[test]
    fn non_object_inputs_are_refused_for_archiving() {
        let err = crate::object::object_symbols(b"plain text, not an object").unwrap_err();
        assert!(err.contains("not an ELF64, Mach-O or COFF object"), "{err}");
    }
}
