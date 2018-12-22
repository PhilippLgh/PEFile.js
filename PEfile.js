const fs = require('fs')
const path = require('path')

const READ = {
  byte: 'readInt8',
  word: 'readUInt16LE',
  dword: 'readUInt32LE'
}

const BYTES = {
  byte: 1,
  word: 2,
  dword: 4
}

class Struct {
  constructor(){
    this.length = 0
  }
  parse(format, inBuffer){
    let relOffset = 0
    format.forEach(el => {
      let parts = el.split(' ')
      let atOffset = 0
      if(parts.length < 2){
        console.log('bad struct format: ', parts)
        return
      }
      if(parts.length === 2) {
        atOffset = relOffset
      }
      if(parts.length === 3) {
        atOffset = parseInt(parts[2])
      }
      let byteLength = parts[0]
      relOffset += BYTES[byteLength]
      let varName = parts[1]
      this[varName] = inBuffer[READ[byteLength]](atOffset)
    })
    this.length = relOffset
  }
}

// note: 'Z'(5A) and 'M'(4D) is reversed due to little endian byte order: 5A4D is 'MZ'
const IMAGE_DOSMZ_SIGNATURE = 0x5A4D
const IMAGE_DOSZM_SIGNATURE = 0x4D5A
class DOS_HEADER extends Struct {
  constructor(inBuffer){
    super()
    this.parse([
      'word e_magic 0x0',     /* 00: MZ Header signature */
      'word e_cblp 0x2',      /* 02: Bytes on last page of file */
      'word e_cp 0x4',        /* 04: Pages in file */
      'word e_crlc 0x6',      /* 06: Relocations */
      'word e_cparhdr 0x8',   /* 08: Size of header in paragraphs */
      'word e_minalloc 0x0a', /* 0a: Minimum extra paragraphs needed */
      'word e_maxalloc 0x0c', /* 0c: Maximum extra paragraphs needed */
      'word e_ss 0x0e',       /* 0e: Initial (relative) SS value */
      'word e_sp',            /* 10: Initial SP value */
      'word e_csum',       /* 12: Checksum */
      'word e_ip',         /* 14: Initial IP value */
      'word e_cs',         /* 16: Initial (relative) CS value */
      'word e_lfarlc',     /* 18: File address of relocation table */
      'word e_ovno',       /* 1a: Overlay number */
      'word e_res[4]',     /* 1c: Reserved words */
      'word e_oemid',      /* 24: OEM identifier (for e_oeminfo) */
      'word e_oeminfo',    /* 26: OEM information; e_oemid specific */
      'word e_res2[10]',   /* 28: Reserved words */
      'dword e_lfanew 0x3c'    /* 3c: Offset to extended header */
    ], inBuffer)

    if( this.e_magic !== IMAGE_DOSMZ_SIGNATURE ) {
      throw new Error('DOS Header magic not found.')
    }

    // Check for sane value in e_lfanew
    if( this.e_lfanew > inBuffer.length ) {
      throw new Error('Invalid e_lfanew value, probably not a PE file')
    }

  }
}

// https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_file_header
const MACHINE_TYPE = {
  0x014c: 'IMAGE_FILE_MACHINE_I386', // x86
  0x0200: 'IMAGE_FILE_MACHINE_IA64', // Intel Itanium
  0x8664: 'IMAGE_FILE_MACHINE_AMD64' // x64
}

const CHARACTERISTICS = {
  /**
   * Relocation information was stripped from the file. 
   * The file must be loaded at its preferred base address. 
   * If the base address is not available, the loader reports an error.
   */
  0x0001: 'IMAGE_FILE_RELOCS_STRIPPED',
  0x0002: 'IMAGE_FILE_EXECUTABLE_IMAGE',    // The file is executable (there are no unresolved external references).
  0x0004: 'IMAGE_FILE_LINE_NUMS_STRIPPED',  // COFF line numbers were stripped from the file.
  0x0008: 'IMAGE_FILE_LOCAL_SYMS_STRIPPED', // COFF symbol table entries were stripped from file.
  0x0010: 'IMAGE_FILE_AGGRESIVE_WS_TRIM',   // Aggressively trim the working set. This value is obsolete.
  0x0020: 'IMAGE_FILE_LARGE_ADDRESS_AWARE', // The application can handle addresses larger than 2 GB.
  0x0080: 'IMAGE_FILE_BYTES_REVERSED_LO',   // The bytes of the word are reversed. This flag is obsolete.
  0x0100: 'IMAGE_FILE_32BIT_MACHINE',       // The computer supports 32-bit words.
  0x0200: 'IMAGE_FILE_DEBUG_STRIPPED',      // Debugging information was removed and stored separately in another file.
  0x0400: 'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP', // If the image is on removable media, copy it to and run it from the swap file.
  0x0800: 'IMAGE_FILE_NET_RUN_FROM_SWAP',   // If the image is on the network, copy it to and run it from the swap file.
  0x1000: 'IMAGE_FILE_SYSTEM',              // The image is a system file.
  0x2000: 'IMAGE_FILE_DLL',                 // The image is a DLL file. While it is an executable file, it cannot be run directly.
  0x4000: 'IMAGE_FILE_UP_SYSTEM_ONLY',      // The file should be run only on a uniprocessor computer.
  0x8000: 'IMAGE_FILE_BYTES_REVERSED_HI',   // The bytes of the word are reversed. This flag is obsolete.
}

class IMAGE_FILE_HEADER extends Struct{
  constructor(inBuffer){
    super()
    this.parse([
      /**
       * The architecture type of the computer. 
       * An image file can only be run on the specified computer or a system that emulates the specified computer. 
       * This member can be one of the following values.
       */
      'word Machine 0x0',
      /**
       * The number of sections. 
       * This indicates the size of the section table, which immediately follows the headers. 
       * Note that the Windows loader limits the number of sections to 96.
       */
      'word NumberOfSections',
      /**
       * The low 32 bits of the time stamp of the image. 
       * This represents the date and time the image was created by the linker. 
       * The value is represented in the number of seconds elapsed since midnight (00:00:00), January 1, 1970, Universal Coordinated Time, according to the system clock.
       */
      'dword TimeDateStamp',
      /**
       * The offset of the symbol table, in bytes, or zero if no COFF symbol table exists.
       */
      'dword PointerToSymbolTable',
      /**
       * The number of symbols in the symbol table.
       */
      'dword NumberOfSymbols',
      /**
       * The size of the optional header, in bytes. This value should be 0 for object files.
       */
      'word SizeOfOptionalHeader',
      /**
       * The characteristics of the image. This member can be one or more of CHARACTERISTICS.
       */
      'word Characteristics'
    ], inBuffer)

    if(MACHINE_TYPE[this.Machine]){
      console.log('machine arch found: ', MACHINE_TYPE[this.Machine])
    }
  }
}

// https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_data_directory
/** from winnt.h
 /* These are indexes into the DataDirectory array /
#define IMAGE_FILE_EXPORT_DIRECTORY		0
#define IMAGE_FILE_IMPORT_DIRECTORY		1
#define IMAGE_FILE_RESOURCE_DIRECTORY		2
#define IMAGE_FILE_EXCEPTION_DIRECTORY		3
#define IMAGE_FILE_SECURITY_DIRECTORY		4
#define IMAGE_FILE_BASE_RELOCATION_TABLE	5
#define IMAGE_FILE_DEBUG_DIRECTORY		6
#define IMAGE_FILE_DESCRIPTION_STRING		7
#define IMAGE_FILE_MACHINE_VALUE		8  /* Mips /
#define IMAGE_FILE_THREAD_LOCAL_STORAGE		9
#define IMAGE_FILE_CALLBACK_DIRECTORY		10
/* Directory Entries, indices into the DataDirectory array /
#define	IMAGE_DIRECTORY_ENTRY_EXPORT		0
#define	IMAGE_DIRECTORY_ENTRY_IMPORT		1
#define	IMAGE_DIRECTORY_ENTRY_RESOURCE		2
#define	IMAGE_DIRECTORY_ENTRY_EXCEPTION		3
#define	IMAGE_DIRECTORY_ENTRY_SECURITY		4
#define	IMAGE_DIRECTORY_ENTRY_BASERELOC		5
#define	IMAGE_DIRECTORY_ENTRY_DEBUG		6
#define	IMAGE_DIRECTORY_ENTRY_COPYRIGHT		7
#define	IMAGE_DIRECTORY_ENTRY_GLOBALPTR		8   /* (MIPS GP) /
#define	IMAGE_DIRECTORY_ENTRY_TLS		9
#define	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG	10
#define	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	11
#define	IMAGE_DIRECTORY_ENTRY_IAT		12  /* Import Address Table /
#define	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	13
#define	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14
*/
const OFFSETS_PE32 = {
  EXPORT_TABLE: 96,
  IMPORT_TABLE: 104,
  RESOURCE_TABLE: 112,
  EXCEPTION_TABLE: 120,
  CERTIFICATE_TABLE: 128, // aka IMAGE_DIRECTORY_ENTRY_SECURITY / SECURITY_TABLE
  BASE_RELOCATION_TABLE: 136,
  DEBUG_TABLE: 144,
  ARCHITECTURE_SPECIFIC_TABLE: 152,
  GLOBAL_PTR_TABLE: 160,
  TLS_TABLE: 168,
  LOAD_CONFIG_TABLE: 176,
  BOUND_IMPORT_TABLE: 184,
  IAT_TABLE: 192,
  DELAY_IMPORT_TABLE: 200,
  CLR_TABLE: 208,
  RESERVED: 216,
}
const OFFSETS_PE32PLUS = {
  EXPORT_TABLE: 112,
  IMPORT_TABLE: 120,
  RESOURCE_TABLE: 128,
  EXCEPTION_TABLE: 136,
  CERTIFICATE_TABLE: 144,
  BASE_RELOCATION_TABLE: 152,
  DEBUG_TABLE: 160,
  ARCHITECTURE_SPECIFIC_TABLE: 168,
  GLOBAL_PTR_TABLE: 176,
  TLS_TABLE: 184,
  LOAD_CONFIG_TABLE: 192,
  BOUND_IMPORT_TABLE: 200,
  IAT_TABLE: 208,
  DELAY_IMPORT_TABLE: 216,
  CLR_TABLE: 224,
  RESERVED: 232,
}
class IMAGE_DATA_DIRECTORY extends Struct {
  constructor(inBuffer){
    super()
    this.parse([
      'dword VirtualAddress',
      'dword Size'
    ], inBuffer)
  }
}

// https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header
const IMAGE_TYPE = {
  IMAGE_NT_OPTIONAL_HDR32_MAGIC : 0x10b, // The file is an executable image.
  IMAGE_NT_OPTIONAL_HDR64_MAGIC : 0x20b, // The file is an executable image.
  IMAGE_ROM_OPTIONAL_HDR_MAGIC : 0x107 // The file is a ROM image.
}
class IMAGE_OPTIONAL_HEADER32 extends Struct {
  constructor(inBuffer){
    super()
    this.parse([
      'word Magic', 
      'byte MajorLinkerVersion',
      'byte MinorLinkerVersion',
      'dword SizeOfCode',
      'dword SizeOfInitializedData',
      'dword SizeOfUninitializedData',
      'dword AddressOfEntryPoint',
      'dword BaseOfCode',
      'dword BaseOfData',
      'dword ImageBase',
      'dword SectionAlignment',
      'dword FileAlignment',
      'word MajorOperatingSystemVersion',
      'word MinorOperatingSystemVersion',
      'word MajorImageVersion',
      'word MinorImageVersion',
      'word MajorSubsystemVersion',
      'word MinorSubsystemVersion',
      'dword Reserved1',
      'dword SizeOfImage',
      'dword SizeOfHeaders',
      'dword CheckSum',
      'word Subsystem',
      'word DllCharacteristics',
      'dword SizeOfStackReserve',
      'dword SizeOfStackCommit',
      'dword SizeOfHeapReserve',
      'dword SizeOfHeapCommit',
      'dword LoaderFlags',
      'dword NumberOfRvaAndSizes'
    ], inBuffer)
    if(this.Magic !== IMAGE_TYPE.IMAGE_NT_OPTIONAL_HDR32_MAGIC 
      && this.Magic !== IMAGE_TYPE.IMAGE_NT_OPTIONAL_HDR64_MAGIC 
      && this.Magic !== IMAGE_TYPE.IMAGE_ROM_OPTIONAL_HDR_MAGIC
    ) {
      throw new Error('IMAGE_OPTIONAL_HEADER parse error: "word Magic" not found or bad value')
    }

    this.parseDataDirectories(inBuffer)
  }
  parseDataDirectories(inBuffer, offset){
    // TODO 
    let isPlus = false
    let OFFSETS = isPlus ? OFFSETS_PE32PLUS : OFFSETS_PE32
    this.DataDirectories = {}
    for (const tableName in OFFSETS) {
      let tableOffset = OFFSETS[tableName]
      this.DataDirectories[tableName] = new IMAGE_DATA_DIRECTORY(inBuffer.slice(tableOffset))
    }
  }
  get CertificateTable(){
    return this.DataDirectories['CERTIFICATE_TABLE']
  }
}

// https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_nt_headers
const IMAGE_NT_SIGNATURE = 0x00004550
class IMAGE_NT_HEADERS extends Struct {
  constructor(inBuffer) {
    super()
    this.parse([
      'dword signature 0x0',    /* 00: signature: "PE"\0\0 */
    ], inBuffer)
    if(this.signature !== IMAGE_NT_SIGNATURE){
      throw new Error('NT header signature not found')
    }
    this.FileHeader = new IMAGE_FILE_HEADER(inBuffer.slice(this.length))
    this.length += this.FileHeader.length
    this.OptionalHeader = new IMAGE_OPTIONAL_HEADER32(inBuffer.slice(this.length))
    this.length += this.FileHeader.SizeOfOptionalHeader // use defined length instead of counted length
  }
}

class IMAGE_SECTION_HEADER extends Struct {
  constructor(inBuffer) {
    super()
    this.parse([

    ], inBuffer)
  }
  /*
  __IMAGE_SECTION_HEADER_format__ = ('IMAGE_SECTION_HEADER',
  ('8s,Name', 'I,Misc,Misc_PhysicalAddress,Misc_VirtualSize',
  'I,VirtualAddress', 'I,SizeOfRawData', 'I,PointerToRawData',
  'I,PointerToRelocations', 'I,PointerToLinenumbers',
  'H,NumberOfRelocations', 'H,NumberOfLinenumbers',
  'I,Characteristics'))
  */
}

// The options for the WIN_CERTIFICATE wRevision member include (but are not limited to) the following.
const CERT_REVISION = {
  WIN_CERT_REVISION_1_0: 0x0100,
  WIN_CERT_REVISION_2_0: 0x0200
}

const CERT_TYPE = {
  0x0001: 'WIN_CERT_TYPE_X509', // bCertificate contains an X.509 Certificate - Not Supported
  0x0002: 'WIN_CERT_TYPE_PKCS_SIGNED_DATA', // bCertificate contains a PKCS#7 SignedData structure
  0x0003: 'WIN_CERT_TYPE_RESERVED_1', // Reserved
  0x0004: 'WIN_CERT_TYPE_TS_STACK_SIGNED' // Terminal Server Protocol Stack Certificate signing  - Not Supported
}

/* 
https://docs.microsoft.com/en-us/windows/desktop/api/wintrust/ns-wintrust-_win_certificate
The Authenticode signature is in a WIN_CERTIFICATE structure, which is declared in Wintrust.h as follows:
typedef struct _WIN_CERTIFICATE
{
    DWORD       dwLength;
    WORD        wRevision;
    WORD        wCertificateType;   
    BYTE        bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
*/
class ATTRIBUTE_CERTIFICATE_ENTRY extends Struct {
  constructor(inBuffer) {
    super()
    this.parse([
      'dword dwLength',           // Specifies the length of the attribute certificate entry. 
      'word wRevision',          // Contains the certificate version number.
      'word wCertificateType'   // Specifies the type of content in bCertificate.
    ], inBuffer)
    
    // The WIN_CERTIFICATE structure's bCertificate member contains a variable-length byte array with the content type specified by wCertificateType. 
    this.bCertificate = inBuffer.slice(this.length, this.length + this.dwLength)

    this.length = this.dwLength

    console.log('cert type is', CERT_TYPE[this.CertificateType])

    // The type supported by Authenticode is WIN_CERT_TYPE_PKCS_SIGNED_DATA, a PKCS#7 SignedData structure. 
    // For details on the Authenticode digital signature format, see Windows Authenticode Portable Executable Signature Format:
    // http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
  }
}


// https://github.com/erocarrera/pefile
// https://msdn.microsoft.com/en-us/library/ms809762.aspx
// http://www.skyfree.org/linux/references/coff.pdf
// https://bytepointer.com/resources/pietrek_in_depth_look_into_pe_format_pt1_figures.htm
class PeFile {

  constructor(filePath){
    this.inBuffer = fs.readFileSync(filePath)
    this.dosHeader = new DOS_HEADER(this.inBuffer)
    console.log('magic', this.dosHeader.e_magic.toString(16))
    
    let nt_headers_offset = this.dosHeader.e_lfanew
    let nt_header_buffer = this.inBuffer.slice(nt_headers_offset)
    this.ntHeader = new IMAGE_NT_HEADERS(nt_header_buffer)
    console.log('machine', this.ntHeader.FileHeader.Machine.toString(16))
    console.log('optional header magic', this.ntHeader.OptionalHeader.Magic.toString(16))

    // Note: location of sections can be controlled from PE header:
    let sections_offset = nt_headers_offset + this.ntHeader.length
    this.parseSections(this.inBuffer, sections_offset)

    this.parseDataDirectories(this.inBuffer)
  }

  parseSections() {

  }

  parseDataDirectories(inBuffer) {
    // this.parseExportTable()
    // this.parseImportTable()
    // this.parseResourceTable()
    // this.parseExceptionTable()
    this.parseCertificateTable(inBuffer)
  }

  parseCertificateTable(inBuffer) {
    // Points to a list of WIN_CERTIFICATE structures, defined in WinTrust.H. 
    // Not mapped into memory as part of the image. Therefore, the VirtualAddress field is a file offset, rather than an RVA.
    let certTable = this.OptionalHeader.CertificateTable
    let address = certTable.VirtualAddress
    let size = certTable.Size

    console.log('address & size of cert table: ', address.toString(16), address, 'size:', size)

    /*
    The virtual address value from the Certificate Table entry in the Optional Header Data Directory is a file offset to the first attribute certificate entry. 
    Subsequent entries are accessed by advancing that entry's dwLength bytes, rounded up to an 8-byte multiple, from the start of the current attribute certificate entry. 
    This continues until the sum of the rounded dwLength values equals the Size value from the Certificates Table entry in the Optional Header Data Directory. 
    If the sum of the rounded dwLength values does not equal the Size value, then either the attribute certificate table or the Size field is corrupted.
    */
    this._CertificateEntries = [ ]

    // 1: Add the first attribute certificate's dwLength value to the starting offset.
    // 2. Round the value from step 1 up to the nearest 8-byte multiple to find the offset of the second attribute certificate entry.
    // 3. Add the offset value from step 2 to the second attribute certificate entry's dwLength value and round up to the nearest 8-byte multiple to determine the offset of the third attribute certificate entry.
    // 4. Repeat step 3 for each successive certificate until the calculated offset equals 0x6000 (0x5000 start + 0x1000 total size), which indicates that you've walked the entire table.
    let offset = address
    let endOfTable = (address + size)
    while(offset < endOfTable){
      // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-attribute-certificate-table-image-only
      let cert_attr = new ATTRIBUTE_CERTIFICATE_ENTRY(inBuffer.slice(address))
      this._CertificateEntries.push(cert_attr)

      // find next entry:
      // 1., 3.
      offset += cert_attr.dwLength
      // 2., 3.
      let nearestMultiple = (Math.ceil(offset / 8) * 8)
      offset = nearestMultiple
    }
  }
  get FileHeader() {
    return this.ntHeader.FileHeader
  }
  get OptionalHeader() {
    return this.ntHeader.OptionalHeader
  }
  get certificateTable() {
    return this._CertificateEntries
  }
}

module.exports = PeFile
