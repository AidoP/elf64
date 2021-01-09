#![no_std]
use core::{fmt, ops::{Deref, DerefMut, Index}};

macro_rules! decode {
    (le; u16 => $b:ident[$i:expr =>]) => {
        u16::from_le_bytes([$b[$i], $b[$i + 1]])
    };
    (be; u16 => $b:ident[$i:expr =>]) => {
        u16::from_be_bytes([$b[$i], $b[$i + 1]])
    };
    (le; u32 => $b:ident[$i:expr =>]) => {
        u32::from_le_bytes([$b[$i], $b[$i + 1], $b[$i + 2], $b[$i + 3]])
    };
    (be; u32 => $b:ident[$i:expr =>]) => {
        u32::from_be_bytes([$b[$i], $b[$i + 1], $b[$i + 2], $b[$i + 3]])
    };
    (le; u64 => $b:ident[$i:expr =>]) => {
        u64::from_le_bytes([$b[$i], $b[$i + 1], $b[$i + 2], $b[$i + 3], $b[$i + 4], $b[$i + 5], $b[$i + 6], $b[$i + 7]])
    };
    (be; u64 => $b:ident[$i:expr =>]) => {
        u64::from_be_bytes([$b[$i], $b[$i + 1], $b[$i + 2], $b[$i + 3], $b[$i + 4], $b[$i + 5], $b[$i + 6], $b[$i + 7]])
    };
}

/// A 64-bit ELF file
/// Does not clone so must live as long as the backing bytes making up the file
pub struct Elf64<'a> {
    bytes: &'a [u8],
    pub header: Header,
    pub byte_order: ByteOrder,
}
impl<'a> Elf64<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, ElfError> {
        let header = Header::new(&bytes[..core::mem::size_of::<Header>()])?;
        let byte_order = header.identifier.byte_order()?;
        Ok(Self {
            bytes,
            header,
            byte_order
        })
    }
    /// Get the section header for the given entry in the section header table.
    /// Like `Elf64::section()` but does not interpret the section header in any way.
    pub fn section_header(&self, index: usize) -> Result<SectionHeader, ElfError> {
        if index > self.header.section_header_count as _ {
            Err(ElfError::NoSection)
        } else {
            let offset = self.header.section_header_size as usize * index + *self.header.section_header as usize;
            SectionHeader::new(&self.bytes[offset..], self.byte_order)
        }
    }
    /// Returns an iterator over each section.
    /// Like `Elf64::section()`, the sections are parsed and typed.
    pub fn sections(&self) -> Sections {
        Sections::new(self.bytes, self.header.clone(), self.byte_order)
    }
    /// Get the section header and a parsed wrapper around the section contents.
    /// See `elf64::Section` for potential section types.
    pub fn section(&self, index: usize) -> Result<Section, ElfError> {
        Section::new(self.bytes, self.section_header(index)?, self.byte_order)
    }
    /// Returns the string table containing the strings for section names.
    pub fn section_string_table(&self) -> Result<StringTable, ElfError> {
        if let Section::StringTable(string_table) = self.section(self.header.string_table())? {
            Ok(string_table)
        } else {
            Err(ElfError::BadSectionType)
        }
    }
}
impl<'a> Deref for Elf64<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C, align(8))]
pub struct Address(u64);
impl<'a> Deref for Address {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<'a> DerefMut for Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[derive(Copy, Clone, Debug)]
#[repr(C, align(8))]
pub struct Offset(u64);
impl<'a> Deref for Offset {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<'a> DerefMut for Offset {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Class {
    Elf64,
    Elf32
}
#[derive(Copy, Clone, Debug)]
pub enum ByteOrder {
    Lsb,
    Msb
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Identifier([u8; 16]);
impl Identifier {
    fn new(bytes: &[u8]) -> Self {
        let mut this = [0; 16];
        this.iter_mut().zip(bytes).for_each(|(v, b)| *v = *b);
        Self(this)
    }
    pub fn valid(&self) -> Result<(), ElfError> {
        // Valid magic bytes
        if !(self[0] == 0x7F && self[1] == b'E' && self[2] == b'L' && self[3] == b'F') {
            Err(ElfError::NotElf)
        } else if self[6] != 1 {
            Err(ElfError::UnsupportedVersion)
        } else if self.class()? != Class::Elf64 {
            Err(ElfError::Not64Bit)
        } else {
            Ok(())
        }
    }
    /// Returns if the elf file is 64 or 32 bit.
    pub fn class(&self) -> Result<Class, ElfError> {
        match self[4] {
            1 => Ok(Class::Elf32),
            2 => Ok(Class::Elf64),
            _ => Err(ElfError::Invalid)
        }
    }
    /// Returns the byte order of the data structures within the file.
    pub fn byte_order(&self) -> Result<ByteOrder, ElfError> {
        match self[5] {
            1 => Ok(ByteOrder::Lsb),
            2 => Ok(ByteOrder::Msb),
            _ => Err(ElfError::Invalid)
        }
    }
    pub fn abi(&self) -> u8 {
        self[7]
    }
    /// Returns the SystemV ABI version specified, or None.
    pub fn is_sysv(&self) -> Option<u8> {
        if self.abi() == 0 {
            Some(self.abi_version())
        } else {
            None
        }
    }
    pub fn abi_version(&self) -> u8 {
        self[8]
    }
}
impl Deref for Identifier {
    type Target = [u8; 16];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct ObjectType(pub u16);
impl ObjectType {
    pub const NONE: Self = Self(0);
    pub const RELOCATABLE: Self = Self(1);
    pub const EXECUTABLE: Self = Self(2);
    pub const SHARED_OBJECT: Self = Self(3);
    pub const CORE_OBJECT: Self = Self(4);
}
impl fmt::Debug for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", match *self {
            Self::NONE => "No Type",
            Self::RELOCATABLE => "Relocatable",
            Self::EXECUTABLE => "Executable",
            Self::SHARED_OBJECT => "Shared Object",
            Self::CORE_OBJECT => "Core Object",
            _ => "Unknown Type"
        }, self.0)
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Header {
    identifier: Identifier,
    object_type: ObjectType,
    machine: u16,
    version: u32,
    entry_point: Address,
    program_header: Offset,
    section_header: Offset,
    flags: u32,
    header_size: u16,
    program_header_size: u16,
    program_header_count: u16,
    section_header_size: u16,
    section_header_count: u16,
    string_table_section: u16
}
impl Header {
    fn new(bytes: &[u8]) -> Result<Self, ElfError> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return Err(ElfError::UnexpectedEOF)
        }
        let identifier = Identifier::new(bytes);
        identifier.valid()?;
        match identifier.byte_order()? {
            ByteOrder::Lsb => {
                let object_type = ObjectType(decode![le; u16 => bytes[16=>]]);
                let machine = decode![le; u16 => bytes[18=>]];
                let version = decode![le; u32 => bytes[20=>]];
                let entry_point = Address(decode![le; u64 => bytes[24=>]]);
                let program_header = Offset(decode![le; u64 => bytes[32=>]]);
                let section_header = Offset(decode![le; u64 => bytes[40=>]]);
                let flags = decode![le; u32 => bytes[48=>]];
                let header_size = decode![le; u16 => bytes[52=>]];
                let program_header_size = decode![le; u16 => bytes[54=>]];
                let program_header_count = decode![le; u16 => bytes[56=>]];
                let section_header_size = decode![le; u16 => bytes[58=>]];
                let section_header_count = decode![le; u16 => bytes[60=>]];
                let string_table_section = decode![le; u16 => bytes[62=>]];
                Ok(Self {
                    identifier,
                    object_type,
                    machine,
                    version,
                    entry_point,
                    program_header,
                    section_header,
                    flags,
                    header_size,
                    program_header_size,
                    program_header_count,
                    section_header_size,
                    section_header_count,
                    string_table_section
                })
            }
            ByteOrder::Msb => {
                let object_type = ObjectType(decode![be; u16 => bytes[16=>]]);
                let machine = decode![be; u16 => bytes[18=>]];
                let version = decode![be; u32 => bytes[20=>]];
                let entry_point = Address(decode![be; u64 => bytes[24=>]]);
                let program_header = Offset(decode![be; u64 => bytes[32=>]]);
                let section_header = Offset(decode![be; u64 => bytes[40=>]]);
                let flags = decode![be; u32 => bytes[48=>]];
                let header_size = decode![be; u16 => bytes[52=>]];
                let program_header_size = decode![be; u16 => bytes[54=>]];
                let program_header_count = decode![be; u16 => bytes[56=>]];
                let section_header_size = decode![be; u16 => bytes[58=>]];
                let section_header_count = decode![be; u16 => bytes[60=>]];
                let string_table_section = decode![be; u16 => bytes[62=>]];
                Ok(Self {
                    identifier,
                    object_type,
                    machine,
                    version,
                    entry_point,
                    program_header,
                    section_header,
                    flags,
                    header_size,
                    program_header_size,
                    program_header_count,
                    section_header_size,
                    section_header_count,
                    string_table_section
                })
            }
        }
    }
    pub fn string_table(&self) -> usize {
        self.string_table_section as _
    }
}

#[derive(Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct SectionType(pub(crate) u32);
impl SectionType {
    pub const UNUSED: Self = Self(0);
    pub const PROGBITS: Self = Self(1);
    pub const SYMBOL_TABLE: Self = Self(2);
    pub const STRING_TABLE: Self = Self(3);
    pub const RELA: Self = Self(4);
    pub const HASH_TABLE: Self = Self(5);
    pub const DYNAMIC: Self = Self(6);
    pub const NOTE: Self = Self(7);
    pub const NO_BITS: Self = Self(8);
    pub const REL: Self = Self(9);
    pub const SHLIB: Self = Self(10);
    pub const DYNAMIC_SYMBOLS: Self = Self(11);
}
impl fmt::Debug for SectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", match *self {
            Self::UNUSED => "Unused",
            Self::PROGBITS => "Program Data",
            Self::SYMBOL_TABLE => "Symbol Table",
            Self::STRING_TABLE => "String Table",
            Self::RELA => "Relocation With Addend",
            Self::HASH_TABLE => "Hash Table",
            Self::DYNAMIC => "Dynamic",
            Self::NOTE => "Compiler Note",
            Self::NO_BITS => "Zeroed Program Data",
            Self::REL => "Relocation Without Addend",
            Self::SHLIB => "Reserved",
            Self::DYNAMIC_SYMBOLS => "Dynamic Symbols",
            _ => "Unknown Type"
        }, self.0)
    }
}
#[derive(Clone)]
#[repr(transparent)]
pub struct SectionAttributes(pub(crate) u64);
impl SectionAttributes {
    pub const WRITE: Self = Self(1);
    pub const ALLOC: Self = Self(2);
    pub const EXEC: Self = Self(4);
}
impl fmt::Debug for SectionAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flags({:b})", self.0)
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct SectionHeader {
    pub name: StringOffset,
    pub section_type: SectionType,
    pub attributes: SectionAttributes,
    pub virtual_address: Address,
    offset: Offset,
    size: u64,
    link: u32,
    info: u32,
    pub alignment: u64,
    entry_size: u64
}
impl SectionHeader {
    fn new(bytes: &[u8], byte_order: ByteOrder) -> Result<Self, ElfError> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return Err(ElfError::UnexpectedEOF)
        }
        match byte_order {
            ByteOrder::Lsb => {
                let name = StringOffset(decode![le; u32 => bytes[0=>]]);
                let section_type = SectionType(decode![le; u32 => bytes[4=>]]);
                let attributes = SectionAttributes(decode![le; u64 => bytes[8=>]]);
                let virtual_address = Address(decode![le; u64 => bytes[16=>]]);
                let offset = Offset(decode![le; u64 => bytes[24=>]]);
                let size = decode![le; u64 => bytes[32=>]];
                let link = decode![le; u32 => bytes[40=>]];
                let info = decode![le; u32 => bytes[44=>]];
                let alignment = decode![le; u64 => bytes[48=>]];
                let entry_size = decode![le; u64 => bytes[56=>]];
                Ok(Self {
                    name,
                    section_type,
                    attributes,
                    virtual_address,
                    offset,
                    size,
                    link,
                    info,
                    alignment,
                    entry_size
                })
            }
            ByteOrder::Msb => {
                let name = StringOffset(decode![be; u32 => bytes[0=>]]);
                let section_type = SectionType(decode![be; u32 => bytes[4=>]]);
                let attributes = SectionAttributes(decode![be; u64 => bytes[8=>]]);
                let virtual_address = Address(decode![be; u64 => bytes[16=>]]);
                let offset = Offset(decode![be; u64 => bytes[24=>]]);
                let size = decode![be; u64 => bytes[32=>]];
                let link = decode![be; u32 => bytes[40=>]];
                let info = decode![be; u32 => bytes[44=>]];
                let alignment = decode![be; u64 => bytes[48=>]];
                let entry_size = decode![be; u64 => bytes[56=>]];
                Ok(Self {
                    name,
                    section_type,
                    attributes,
                    virtual_address,
                    offset,
                    size,
                    link,
                    info,
                    alignment,
                    entry_size
                })
            }
        }
    }
}

pub enum Section<'a> {
    Null,
    StringTable(StringTable<'a>),
    SymbolTable(SymbolTable<'a>),
    Unknown(SectionHeader)
}
impl<'a> Section<'a> {
    pub fn new(bytes: &'a [u8], header: SectionHeader, byte_order: ByteOrder) -> Result<Self, ElfError> {
        match header.section_type {
            SectionType::UNUSED => Ok(Self::Null),
            SectionType::STRING_TABLE => {
                let start = *header.offset as usize;
                let size = header.size as usize;
                if start + size > bytes.len() {
                    Err(ElfError::UnexpectedEOF)
                } else {
                    Ok(Self::StringTable(StringTable {
                        header,
                        bytes: &bytes[start..start + size]
                    }))
                }
            }
            SectionType::SYMBOL_TABLE => {
                let start = *header.offset as usize;
                let size = header.size as usize;
                if start + size > bytes.len() {
                    Err(ElfError::UnexpectedEOF)
                } else {
                    Ok(Self::SymbolTable(SymbolTable {
                        header,
                        bytes: &bytes[start..start + size],
                        byte_order
                    }))
                }
            }
            _ => Ok(Self::Unknown(header))
        }
    }
    pub fn header(&self) -> Option<&SectionHeader> {
        match self {
            Self::Null => None,
            Self::StringTable(string_table) => Some(&string_table.header),
            Self::SymbolTable(symbol_table) => Some(&symbol_table.header),
            Self::Unknown(header) => Some(header)
        }
    }
}

pub struct Sections<'a> {
    index: usize,
    header: Header,
    byte_order: ByteOrder,
    bytes: &'a [u8]
}
impl<'a> Sections<'a> {
    pub fn new(bytes: &'a [u8], header: Header, byte_order: ByteOrder) -> Self {
        Self {
            index: 0,
            header,
            byte_order,
            bytes
        }
    }
}
impl<'a> Iterator for Sections<'a> {
    type Item = Section<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index > self.header.section_header_count as _ {
            None
        } else {
            let offset = self.header.section_header_size as usize * self.index + *self.header.section_header as usize;
            self.index += 1;
            let header = SectionHeader::new(&self.bytes[offset..], self.byte_order).ok()?;
            Section::new(self.bytes, header, self.byte_order).ok()
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct SegmentType(u32);
impl SegmentType {
    pub const NULL: Self = Self(0);
    pub const LOAD: Self = Self(1);
    pub const DYNAMIC: Self = Self(2);
    pub const INTERPRETER: Self = Self(3);
    pub const NOTE: Self = Self(4);
    pub const SHLIB: Self = Self(5);
    pub const PROGRAM_HEADER: Self = Self(6);
}
impl fmt::Debug for SegmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", match *self {
            Self::NULL => "Unused",
            Self::LOAD => "Loadable Segment",
            Self::DYNAMIC => "Dynamic Linking Table",
            Self::INTERPRETER => "Interpreter Path",
            Self::NOTE => "Compiler Note",
            Self::SHLIB => "Reserved",
            Self::PROGRAM_HEADER => "Program Header",
            _ => "Unknown Type"
        }, self.0)
    }
}
#[derive(Clone)]
#[repr(transparent)]
pub struct SegmentAttributes(u32);
impl SegmentAttributes {
    pub const EXECUTE: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const READ: Self = Self(4);
}
impl fmt::Debug for SegmentAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flags({:b})", self.0)
    }
}


#[repr(C)]
pub struct ProgramHeader {
    pub segment_type: SegmentType,
    pub attributes: SegmentAttributes,
    pub offset: Offset,
    pub virtual_address: Address,
    pub physical_address: Address,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64
}
impl ProgramHeader {
    pub fn new(bytes: &[u8], byte_order: ByteOrder) -> Self {
        match byte_order {
            ByteOrder::Lsb => {
                let segment_type = SegmentType(decode![le; u32 => bytes[0=>]]);
                let attributes = SegmentAttributes(decode![le; u32 => bytes[4=>]]);
                let offset = Offset(decode![le; u64 => bytes[8=>]]);
                let virtual_address = Address(decode![le; u64 => bytes[16=>]]);
                let physical_address = Address(decode![le; u64 => bytes[24=>]]);
                let file_size = decode![le; u64 => bytes[32=>]];
                let memory_size = decode![le; u64 => bytes[40=>]];
                let alignment = decode![le; u64 => bytes[48=>]];
                Self {
                    segment_type,
                    attributes,
                    offset,
                    virtual_address,
                    physical_address,
                    file_size,
                    memory_size,
                    alignment
                }
            }
            ByteOrder::Msb => {
                let segment_type = SegmentType(decode![be; u32 => bytes[0=>]]);
                let attributes = SegmentAttributes(decode![be; u32 => bytes[4=>]]);
                let offset = Offset(decode![be; u64 => bytes[8=>]]);
                let virtual_address = Address(decode![be; u64 => bytes[16=>]]);
                let physical_address = Address(decode![be; u64 => bytes[24=>]]);
                let file_size = decode![be; u64 => bytes[32=>]];
                let memory_size = decode![be; u64 => bytes[40=>]];
                let alignment = decode![be; u64 => bytes[48=>]];
                Self {
                    segment_type,
                    attributes,
                    offset,
                    virtual_address,
                    physical_address,
                    file_size,
                    memory_size,
                    alignment
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct StringOffset(pub(crate) u32);
impl StringOffset {
    pub fn equal(&self, string_table: &StringTable, string: &[u8]) -> Option<bool> {
        string_table.get(*self).map(|this| this.iter().zip(string).all(|(l, r)| *l == *r))
    }
    /// Get the string as a Rust `&str`. Will return None if the StringOffset does not point to a valid UTF-8 string.
    pub fn str<'a>(&self, string_table: &'a StringTable) -> Option<&'a str> {
        string_table.get(*self).map(|bytes| core::str::from_utf8(bytes).ok()).flatten()
    }
    #[inline(always)]
    pub fn bytes<'a>(&self, string_table: &'a StringTable) -> Option<&'a [u8]> {
        string_table.get(*self)
    }
}
impl Deref for StringOffset {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for StringOffset {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone)]
pub struct StringTable<'a> {
    pub header: SectionHeader,
    pub bytes: &'a [u8]
}
impl<'a> StringTable<'a> {
    /// Gets the string from the string table for a given string offset.
    /// The string is a slice over the 
    pub fn get(&self, index: StringOffset) -> Option<&[u8]> {
        let mut end = *index as usize;
        while *self.bytes.get(end)? != b'\0' {
            end += 1;
        }
        Some(&self.bytes[*index as usize..end])
    }
    /// Gets a null-terminated string
    /// # Safety
    /// `index` must be within table bounds. Furthermore, null-termination relies on file correctness and as such you must ensure you do not read out-of-bounds.
    pub unsafe fn get_raw(&self, index: usize) -> *const u8 {
        self.bytes.as_ptr().add(index)
    }
}

pub struct SymbolTable<'a> {
    pub header: SectionHeader,
    pub bytes: &'a [u8],
    byte_order: ByteOrder
}
impl<'a> SymbolTable<'a> {
    /// Retrieve the symbol entry by index
    pub fn get(&self, index: usize) -> Option<Symbol> {
        let start = self.header.entry_size as usize * index;
        let end = start + self.header.entry_size as usize;
        if end > self.bytes.len() {
            None
        } else {
            Some(Symbol::new(&self.bytes[start..end], self.byte_order))
        }
    }
    pub fn symbols<'b>(&'b self) -> Symbols<'a, 'b> {
        Symbols {
            index: 0,
            symbol_table: self
        }
    }
    /// Look for a symbol by name
    pub fn lookup(&self, string_table: &StringTable, name: &[u8]) -> Option<Symbol> {
        self.symbols().find(|symbol| symbol.name.equal(string_table, name).unwrap_or(false))
    }
}
/// Iterator over each symbol in a symbol table
pub struct Symbols<'a, 'b> {
    index: usize,
    symbol_table: &'b SymbolTable<'a>
}
impl<'a, 'b> Iterator for Symbols<'a, 'b> {
    type Item = Symbol;
    fn next(&mut self) -> Option<Self::Item> {
        let symbol = self.symbol_table.get(self.index);
        self.index += 1;
        symbol
    }
}

pub struct SymbolInfo {
    pub visibility: u8,
    pub symbol_type: u8
}
impl SymbolInfo {
    pub const LOCAL: u8 = 0;
    pub const GLOBAL: u8 = 1;
    pub const WEAK: u8 = 2;

    pub const NO_TYPE: u8 = 0;
    pub const OBJECT: u8 = 1;
    pub const FUNCTION: u8 = 2;
    pub const SECTION: u8 = 3;
    pub const FILE: u8 = 4;
}
pub struct Symbol {
    pub name: StringOffset,
    pub info: SymbolInfo,
    pub section_index: u16,
    pub value: Address,
    pub size: u64
}
impl Symbol {
    pub fn new(bytes: &[u8], byte_order: ByteOrder) -> Self {
        match byte_order {
            ByteOrder::Lsb => {
                let name = StringOffset(decode![le; u32 => bytes[0=>]]);
                let info = SymbolInfo {
                    visibility: (bytes[4] & 0xF0) >> 4,
                    symbol_type: bytes[4] & 0x0F
                };
                let section_index = decode![le; u16 => bytes[6=>]];
                let value = Address(decode![le; u64 => bytes[8=>]]);
                let size = decode![le; u64 => bytes[16=>]];
                Self {
                    name,
                    info,
                    section_index,
                    value,
                    size
                }
            }
            ByteOrder::Msb => {
                let name = StringOffset(decode![be; u32 => bytes[0=>]]);
                let info = SymbolInfo {
                    visibility: (bytes[4] & 0xF0) >> 4,
                    symbol_type: bytes[4] & 0x0F
                };
                let section_index = decode![be; u16 => bytes[6=>]];
                let value = Address(decode![be; u64 => bytes[8=>]]);
                let size = decode![be; u64 => bytes[16=>]];
                Self {
                    name,
                    info,
                    section_index,
                    value,
                    size
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ElfError {
    UnexpectedEOF,
    NotElf,
    Not64Bit,
    Invalid,
    UnsupportedVersion,
    BadSectionType,
    NoSection
}