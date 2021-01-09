use std::{fs::File, io::{Read, Write}};
use elf64::Elf64;

#[test]
pub fn load_elf() {
    let mut file = File::open("tests/test.so").unwrap();
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).unwrap();

    let elf = Elf64::new(&bytes).unwrap();
    let section_strings = elf.section_string_table().unwrap();
    let mut symtab = None;
    let mut strtab = None;

    for section in elf.sections() {
        use elf64::Section;
        match section {
            Section::SymbolTable(symbol_table) => symtab = Some(symbol_table),
            Section::StringTable(string_table) if string_table.header.name.equal(&section_strings, b".strtab").unwrap() => strtab = Some(string_table),
            _ => ()
        }
    }

    let symtab = symtab.unwrap();
    let strtab = strtab.unwrap();

    for symbol in symtab.symbols() {
        println!("Symbol {:?} == 0x{:x}", symbol.name.str(&strtab), *symbol.value)
    }
}