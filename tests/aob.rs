use practice_tool_core::aob::{aob_direct, aob_indirect, aob_indirect_twice, find_aobs, PeFile};

// A PE32+ file with two sections, whose virtual addresses differ from their
// file offsets. Keep section lengths exact to exercise truncated patterns.
fn pe_fixture(sections: [&[u8]; 2]) -> Vec<u8> {
    let mut image = vec![0; 0x600];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    image[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    image[0x86..0x88].copy_from_slice(&2_u16.to_le_bytes());
    image[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    image[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    image[0xb8..0xbc].copy_from_slice(&0x1000_u32.to_le_bytes());
    image[0xbc..0xc0].copy_from_slice(&0x200_u32.to_le_bytes());
    image[0xd0..0xd4].copy_from_slice(&0x3000_u32.to_le_bytes());
    image[0xd4..0xd8].copy_from_slice(&0x200_u32.to_le_bytes());

    for (index, bytes) in sections.into_iter().enumerate() {
        let header = 0x188 + index * 40;
        let file_offset = 0x200 * (index + 1);
        let virtual_address = 0x1000 * (index + 1);
        image[header + 8..header + 12].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        image[header + 12..header + 16].copy_from_slice(&(virtual_address as u32).to_le_bytes());
        image[header + 16..header + 20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        image[header + 20..header + 24].copy_from_slice(&(file_offset as u32).to_le_bytes());
        image[file_offset..file_offset + bytes.len()].copy_from_slice(bytes);
    }
    image
}

#[test]
fn scans_wildcards_in_all_address_strategies() {
    let image = pe_fixture([&[0x48, 0x8b, 0x0d], &[
        0, 0x48, 0x8b, 0x0d, 0x10, 0, 0, 0, 0x90, 0x48, 0x8b, 0x0d, 0x20, 0, 0, 0, 0x90,
    ]]);
    let pe = PeFile::from_bytes(&image).unwrap();
    let patterns = ["de ad be ef", "48 8b 0d ? ?? ? ?? 90"];

    assert_eq!(aob_direct("direct", &patterns, true).find(&pe), Some(("direct", 0x2001)));
    assert_eq!(aob_indirect("indirect", &patterns, 3, false).find(&pe), Some(("indirect", 0x10)));
    assert_eq!(
        aob_indirect_twice("twice", &patterns, 3, 7, true).find(&pe),
        Some(("twice", 0x2018))
    );
}

#[test]
fn preserves_pattern_and_section_priority() {
    let image = pe_fixture([&[0x90, 0x90], &[0x48, 0x8b, 0x90]]);
    let pe = PeFile::from_bytes(&image).unwrap();

    assert_eq!(
        aob_direct("priority", &["48 8b", "90"], false).find(&pe),
        Some(("priority", 0x2000))
    );
    assert_eq!(aob_direct("first", &["90"], false).find(&pe), Some(("first", 0x1000)));
    assert_eq!(aob_direct("missing", &["ff ?"], false).find(&pe), None);
    assert_eq!(aob_indirect("missing", &["ff ?"], 0, false).find(&pe), None);
    assert_eq!(aob_indirect_twice("missing", &["ff ?"], 0, 0, false).find(&pe), None);
}

#[test]
fn collects_matches_for_borrowed_patterns() {
    let image = pe_fixture([&[0x90], &[0x48, 0x8b, 0x90]]);
    let pe = PeFile::from_bytes(&image).unwrap();
    let name = String::from("borrowed");
    let pattern = String::from("48 ? 90");
    let patterns = [pattern.as_str()];
    let scans = [
        aob_direct(&name, &patterns, true),
        aob_direct("missing", &["ff ?"], false),
        aob_direct("first", &["90"], false),
    ];

    assert_eq!(find_aobs(&pe, &scans), vec![(name.as_str(), 0x2000), ("first", 0x1000)]);
}

#[test]
fn rejects_empty_and_malformed_signatures() {
    let image = pe_fixture([&[0x48, 0x8b, 0x90], &[]]);
    let pe = PeFile::from_bytes(&image).unwrap();
    for pattern in ["", "   ", "GG", "48 ?G 90", "48 100 90"] {
        assert_eq!(aob_direct("invalid", &[pattern], false).find(&pe), None, "{pattern:?}");
    }
    assert_eq!(aob_direct("valid", &["GG", "8b 90"], false).find(&pe), Some(("valid", 0x1001)));
}

#[test]
fn accepts_whitespace_between_bytes() {
    let image = pe_fixture([&[0x48, 0x8b, 0x90], &[]]);
    let pe = PeFile::from_bytes(&image).unwrap();
    assert_eq!(
        aob_direct("spaced", &[" \t48  8b\r\n?  "], false).find(&pe),
        Some(("spaced", 0x1000))
    );
}

#[test]
fn reads_relative_displacements_as_signed() {
    let image = pe_fixture([&[0; 16], &[0, 0x48, 0x8b, 0x05, 0, 0xf0, 0xff, 0xff, 0x90]]);
    let pe = PeFile::from_bytes(&image).unwrap();
    let patterns = ["48 8b 05 ? ? ? ? 90"];
    assert_eq!(
        aob_indirect_twice("relative", &patterns, 3, 7, true).find(&pe),
        Some(("relative", 0x1008))
    );
    assert_eq!(
        aob_indirect("unsigned", &patterns, 3, false).find(&pe),
        Some(("unsigned", 0xffff_f000))
    );
}

#[test]
fn skips_truncated_indirect_reads() {
    let image = pe_fixture([&[0x48, 0x8b, 0x05], &[0x48, 0x8b, 0x05, 0x10, 0, 0, 0]]);
    let pe = PeFile::from_bytes(&image).unwrap();
    let patterns = ["48 8b 05"];
    assert_eq!(aob_indirect("value", &patterns, 3, false).find(&pe), Some(("value", 0x10)));
    assert_eq!(
        aob_indirect_twice("relative", &patterns, 3, 7, true).find(&pe),
        Some(("relative", 0x2017))
    );
}

#[test]
fn rejects_unresolvable_addresses() {
    let image = pe_fixture([&[0x48, 0x8b, 0x05, 0, 0, 0, 0x80], &[]]);
    let pe = PeFile::from_bytes(&image).unwrap();
    let patterns = ["48 8b 05"];
    assert_eq!(aob_indirect("offset", &patterns, usize::MAX, false).find(&pe), None);
    assert_eq!(aob_indirect_twice("offset", &patterns, usize::MAX, 7, true).find(&pe), None);
    assert_eq!(aob_indirect_twice("overflow", &patterns, 3, usize::MAX, true).find(&pe), None);
    assert_eq!(aob_indirect_twice("negative", &patterns, 3, 7, true).find(&pe), None);
}

#[test]
fn continues_after_unresolvable_relative_match() {
    let image = pe_fixture([
        &[0x48, 0x8b, 0x05, 0, 0, 0, 0x80, 0x90, 0x48, 0x8b, 0x05, 0x10, 0, 0, 0, 0x90],
        &[],
    ]);
    let pe = PeFile::from_bytes(&image).unwrap();
    assert_eq!(
        aob_indirect_twice("relative", &["48 8b 05 ? ? ? ? 90"], 3, 7, true).find(&pe),
        Some(("relative", 0x101f))
    );
}
