//
//  MachOParser.swift
//  AltSign
//
//  Created by Magesh K on 07/07/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation

public enum MachOParserError: Error {
    case invalidMachO       // The binary structure is invalid or malformed.
    case missingSignature   // The binary does not contain a code signature block.
}

/**
 Swift Parser for extracting code signature metadata (ex: Entitlements and Requirements)
 from single-arch (thin) and multi-arch (FAT) Mach-O binaries 
 based on public Mach-O specification
 */
public struct MachOParser {

    // Magic constants
    private static let FAT_MAGIC: UInt32 = 0xcafebabe       // FAT binary magic (Big-Endian)
    private static let FAT_CIGAM: UInt32 = 0xbebafeca       // FAT binary magic (Little-Endian)
    private static let FAT_MAGIC_64: UInt32 = 0xcafebabf    // 64-bit FAT binary magic (Big-Endian)
    private static let FAT_CIGAM_64: UInt32 = 0xbfbafeca    // 64-bit FAT binary magic (Little-Endian)

    private static let MH_MAGIC: UInt32 = 0xfeedface        // 32-bit Mach-O magic (Big-Endian)
    private static let MH_CIGAM: UInt32 = 0xcefaedfe        // 32-bit Mach-O magic (Little-Endian)
    private static let MH_MAGIC_64: UInt32 = 0xfeedfacf     // 64-bit Mach-O magic (Big-Endian)
    private static let MH_CIGAM_64: UInt32 = 0xcffaedfe     // 64-bit Mach-O magic (Little-Endian)

    private static let LC_CODE_SIGNATURE: UInt32 = 0x1d     // Load command type for code signatures

    private static let SUPERBLOB_MAGIC: UInt32 = 0xfade0cc0  // SuperBlob signature magic
    private static let BLOB_MAGIC_REQ: UInt32 = 0xfade7171   // Requirements blob magic
    private static let BLOB_MAGIC_ENT: UInt32 = 0xfade7172   // Entitlements blob magic

    /**
     Extracts the XML entitlements string from a Mach-O binary at the specified URL.

     - Parameter url: The file URL of the target binary.
     - Returns: The XML entitlements string.
     - Throws: `MachOParserError` if parsing fails or if no code signature exists.
     */
    public static func extractEntitlements(from url: URL) throws -> String {
        verboseLog("[AltSign] MachOParser.extractEntitlements starting for \(url.path)")
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let entitlements = try extractBlob(from: data, slotType: 5) // CSSLOT_ENTITLEMENTS = 5
        verboseLog("[AltSign] MachOParser.extractEntitlements succeeded, length: \(entitlements.count) chars")
        return entitlements
    }

    /**
     Extracts the requirements string from a Mach-O binary at the specified URL.

     - Parameter url: The file URL of the target binary.
     - Returns: The binary requirements string.
     - Throws: `MachOParserError` if parsing fails or if no code signature exists.
     */
    public static func extractRequirements(from url: URL) throws -> String {
        verboseLog("[AltSign] MachOParser.extractRequirements starting for \(url.path)")
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let requirements = try extractBlob(from: data, slotType: 2) // CSSLOT_REQUIREMENTS = 2
        verboseLog("[AltSign] MachOParser.extractRequirements succeeded, length: \(requirements.count) chars")
        return requirements
    }

    /**
     Inspects the binary headers to determine if the file is a single-arch (thin) Mach-O
     or a universal (FAT) binary, and routes the parsing accordingly.

     - Parameters:
       - data: The binary file data.
       - slotType: The target code signature slot type.
     - Returns: The extracted UTF-8 payload.
     - Throws: `MachOParserError` if the magic headers are invalid or extraction fails.
     */
    private static func extractBlob(from data: Data, slotType: UInt32) throws -> String {
        verboseLog("[AltSign] MachOParser.extractBlob starting, data size: \(data.count) bytes, slotType: \(slotType)")
        guard data.count >= 4 else {
            verboseLog("[AltSign] MachOParser.extractBlob error: data too short (\(data.count) bytes)")
            throw MachOParserError.invalidMachO
        }
        let magic = data.readUInt32(at: 0)
        
        // If the binary starts with universal FAT headers, iterate through architectural slices.
        if magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64 {
            let swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64)
            let is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64)
            
            let numArchs = swap ? data.readUInt32(at: 4).byteSwapped : data.readUInt32(at: 4)
            let archHeaderSize = is64 ? 32 : 20
            verboseLog("[AltSign] MachOParser.extractBlob: FAT binary detected. Slice count: \(numArchs), 64-bit: \(is64), swap: \(swap)")
            
            for i in 0..<Int(numArchs) {
                let offset = 8 + i * archHeaderSize
                let sliceOffset = is64 ?
                    (swap ? data.readUInt64(at: offset + 8).byteSwapped : data.readUInt64(at: offset + 8)) :
                    UInt64(swap ? data.readUInt32(at: offset + 8).byteSwapped : data.readUInt32(at: offset + 8))
                
                let sliceSize = is64 ?
                    (swap ? data.readUInt64(at: offset + 16).byteSwapped : data.readUInt64(at: offset + 16)) :
                    UInt64(swap ? data.readUInt32(at: offset + 12).byteSwapped : data.readUInt32(at: offset + 12))
                
                verboseLog("[AltSign] MachOParser.extractBlob: slice \(i) - offset: \(sliceOffset), size: \(sliceSize)")
                guard Int(sliceOffset) + Int(sliceSize) <= data.count else {
                    verboseLog("[AltSign] MachOParser.extractBlob warning: slice \(i) bounds exceed total data size")
                    continue
                }
                let sliceData = data.subdata(in: Int(sliceOffset)..<Int(sliceOffset + sliceSize))
                if let result = try? extractFromThin(sliceData, slotType: slotType) {
                    verboseLog("[AltSign] MachOParser.extractBlob: successfully extracted slot \(slotType) from slice \(i)")
                    return result
                }
            }
        } else {
            verboseLog("[AltSign] MachOParser.extractBlob: thin binary detected (magic: \(String(format: "0x%08x", magic)))")
            // Otherwise, parse it directly as a single-architecture (thin) binary.
            return try extractFromThin(data, slotType: slotType)
        }
        verboseLog("[AltSign] MachOParser.extractBlob error: missing signature blob")
        throw MachOParserError.missingSignature
    }

    /**
     Parses a single architecture (thin) Mach-O file, iterating through its load commands
     to locate the code signature block (`LC_CODE_SIGNATURE`).

     - Parameters:
       - data: The single-architecture binary data.
       - slotType: The target code signature slot type.
     - Returns: The extracted UTF-8 payload.
     - Throws: `MachOParserError` if headers are invalid or the signature block is missing.
     */
    private static func extractFromThin(_ data: Data, slotType: UInt32) throws -> String {
        verboseLog("[AltSign] MachOParser.extractFromThin starting, size: \(data.count) bytes")
        guard data.count >= 28 else {
            verboseLog("[AltSign] MachOParser.extractFromThin error: data too short (\(data.count) bytes)")
            throw MachOParserError.invalidMachO
        }
        let magic = data.readUInt32(at: 0)
        
        guard magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64 else {
            verboseLog("[AltSign] MachOParser.extractFromThin error: invalid magic header \(String(format: "0x%08x", magic))")
            throw MachOParserError.invalidMachO
        }
        
        let swap = (magic == MH_CIGAM || magic == MH_CIGAM_64)
        let is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
        
        let ncmds = swap ? data.readUInt32(at: 16).byteSwapped : data.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        verboseLog("[AltSign] MachOParser.extractFromThin: thin header parsed. Commands count: \(ncmds), 64-bit: \(is64), swap: \(swap)")
        
        var offset = headerSize
        // Iterate through all load commands in the Mach-O header
        for i in 0..<Int(ncmds) {
            guard offset + 8 <= data.count else {
                verboseLog("[AltSign] MachOParser.extractFromThin error: load command offset out of bounds at command index \(i)")
                throw MachOParserError.invalidMachO
            }
            let cmd = swap ? data.readUInt32(at: offset).byteSwapped : data.readUInt32(at: offset)
            let cmdsize = swap ? data.readUInt32(at: offset + 4).byteSwapped : data.readUInt32(at: offset + 4)
            
            // If the command represents the Code Signature, parse its sub-data
            if cmd == LC_CODE_SIGNATURE {
                guard offset + 16 <= data.count else {
                    verboseLog("[AltSign] MachOParser.extractFromThin error: LC_CODE_SIGNATURE command offset out of bounds")
                    throw MachOParserError.invalidMachO
                }
                let dataoff = swap ? data.readUInt32(at: offset + 8).byteSwapped : data.readUInt32(at: offset + 8)
                let datasize = swap ? data.readUInt32(at: offset + 12).byteSwapped : data.readUInt32(at: offset + 12)
                
                verboseLog("[AltSign] MachOParser.extractFromThin: found LC_CODE_SIGNATURE - offset: \(dataoff), size: \(datasize)")
                guard Int(dataoff) + Int(datasize) <= data.count else {
                    verboseLog("[AltSign] MachOParser.extractFromThin error: LC_CODE_SIGNATURE segment out of bounds")
                    throw MachOParserError.invalidMachO
                }
                return try parseSignatureBlob(data.subdata(in: Int(dataoff)..<Int(dataoff + datasize)), slotType: slotType)
            }
            offset += Int(cmdsize)
        }
        verboseLog("[AltSign] MachOParser.extractFromThin error: LC_CODE_SIGNATURE load command not found")
        throw MachOParserError.missingSignature
    }

    /**
     Parses the Embedded Code Signature Blob (SuperBlob) structure, looking up the specified slot
     (e.g. Entitlements = 5, Requirements = 2) and extracting the raw UTF-8 payload.

     - Parameters:
       - data: The binary segment containing the code signature.
       - slotType: The target code signature slot type.
     - Returns: The extracted UTF-8 payload.
     - Throws: `MachOParserError` if parsing fails.
     */
    private static func parseSignatureBlob(_ data: Data, slotType: UInt32) throws -> String {
        verboseLog("[AltSign] MachOParser.parseSignatureBlob starting, size: \(data.count) bytes")
        guard data.count >= 12 else {
            verboseLog("[AltSign] MachOParser.parseSignatureBlob error: segment too short (\(data.count) bytes)")
            throw MachOParserError.invalidMachO
        }
        
        // SuperBlob magic number is always Big-Endian 0xfade0cc0
        let magic = data.readUInt32BigEndian(at: 0)
        guard magic == SUPERBLOB_MAGIC else {
            verboseLog("[AltSign] MachOParser.parseSignatureBlob error: invalid SuperBlob magic \(String(format: "0x%08x", magic))")
            throw MachOParserError.invalidMachO
        }
        
        let count = data.readUInt32BigEndian(at: 8)
        verboseLog("[AltSign] MachOParser.parseSignatureBlob: SuperBlob count = \(count)")
        
        // Walk through each sub-blob slot in the SuperBlob
        for i in 0..<Int(count) {
            let offset = 12 + i * 8
            guard offset + 8 <= data.count else {
                verboseLog("[AltSign] MachOParser.parseSignatureBlob error: sub-blob slot \(i) index out of bounds")
                throw MachOParserError.invalidMachO
            }
            let type = data.readUInt32BigEndian(at: offset)
            let blobOffset = data.readUInt32BigEndian(at: offset + 4)
            
            // If we found the target slot, parse the Blob header and payload
            if type == slotType {
                let absOffset = Int(blobOffset)
                verboseLog("[AltSign] MachOParser.parseSignatureBlob: found matching slot type \(type) at relative offset \(absOffset)")
                guard absOffset + 8 <= data.count else {
                    verboseLog("[AltSign] MachOParser.parseSignatureBlob error: target blob header out of bounds")
                    throw MachOParserError.invalidMachO
                }
                let blobMagic = data.readUInt32BigEndian(at: absOffset)
                let length = data.readUInt32BigEndian(at: absOffset + 4)
                
                // Embedded blobs have magic prefix 0xfade7171 (requirements) or 0xfade7172 (entitlements)
                guard blobMagic == BLOB_MAGIC_REQ || blobMagic == BLOB_MAGIC_ENT else {
                    verboseLog("[AltSign] MachOParser.parseSignatureBlob error: invalid sub-blob magic \(String(format: "0x%08x", blobMagic))")
                    throw MachOParserError.invalidMachO
                }
                
                let payloadLength = Int(length) - 8
                guard absOffset + 8 + payloadLength <= data.count else {
                    verboseLog("[AltSign] MachOParser.parseSignatureBlob error: payload out of bounds")
                    throw MachOParserError.invalidMachO
                }
                let payload = data.subdata(in: (absOffset + 8)..<(absOffset + 8 + payloadLength))
                
                if let result = String(data: payload, encoding: .utf8) {
                    verboseLog("[AltSign] MachOParser.parseSignatureBlob: successfully decoded payload, length \(result.count)")
                    return result
                } else {
                    verboseLog("[AltSign] MachOParser.parseSignatureBlob error: failed to decode payload as UTF-8 string")
                }
            }
        }
        verboseLog("[AltSign] MachOParser.parseSignatureBlob error: slot \(slotType) not found")
        throw MachOParserError.missingSignature
    }
}

fileprivate extension Data {
    // Read at offset a 32 bit UInt
    func readUInt32(at offset: Int) -> UInt32 {
        guard offset + 4 <= self.count else { return 0 }
        return self.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
    }
    
    // Read at offset a 64 bit UInt
    func readUInt64(at offset: Int) -> UInt64 {
        guard offset + 8 <= self.count else { return 0 }
        return self.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self) }
    }
    
    // Read at offset a 32 bit UInt and convert it to host type (bigEndian)
    func readUInt32BigEndian(at offset: Int) -> UInt32 {
        return UInt32(bigEndian: readUInt32(at: offset))
    }
}
