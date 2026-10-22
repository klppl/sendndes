import Foundation
import Testing
@testable import NdesCore

@Suite struct MetadataTests {
    nonisolated(unsafe) static let cases = vectors["metadata"] as! [JSONObject]

    @Test(arguments: cases.indices)
    func writerEncodings(_ i: Int) throws {
        let c = MetadataTests.cases[i]
        let input = c["input"] as! JSONObject
        let desc = c["description"] as! String
        let build = {
            try Metadata(nameUTF8: hex(input["name_hex"]), dirUTF8: hex(input["dir_hex"]),
                         mtime: i64(input["mtime"]), mimeUTF8: hex(input["mime_hex"]), rev: i64(input["rev"]), size: i64(input["size"]))
        }
        if let err = c["error"] as? String {
            let got = errorClass { _ = try build().paddedPlaintext() }
            #expect(got == err, "\(desc)")
            return
        }
        let m = try build()
        let json = m.canonicalJSON()
        #expect(json == hex(c["canonical_json"]), "\(desc)")
        let padded = try m.paddedPlaintext()
        #expect(padded.count == c["padded_len"] as! Int, "\(desc)")
        #expect(padded.prefix(json.count).elementsEqual(json))
        #expect(padded.dropFirst(json.count).allSatisfy { $0 == 0x20 })
        // The reader accepts exactly what the writer wrote.
        #expect(try Metadata.parse(padded: padded) == m, "\(desc)")
    }

    func padded(_ s: String) -> [UInt8] {
        var b = Array(s.utf8)
        while b.count % 512 != 0 { b.append(0x20) }
        return b
    }

    @Test func int64Boundaries() throws {
        let maxJ = #"{"name":"a","dir":"","mtime":9223372036854775807,"mime":"","rev":9223372036854775807,"size":0}"#
        let minJ = #"{"name":"a","dir":"","mtime":-9223372036854775808,"mime":"","rev":1,"size":0}"#
        #expect(try Metadata.parse(padded: padded(maxJ)).mtime == Int64.max)
        #expect(try Metadata.parse(padded: padded(minJ)).mtime == Int64.min)
        for bad in ["9223372036854775808", "-9223372036854775809", "99999999999999999999"] {
            let j = #"{"name":"a","dir":"","mtime":\#(bad),"mime":"","rev":1,"size":0}"#
            #expect(errorClass { _ = try Metadata.parse(padded: padded(j)) } == "metadata", "\(bad)")
        }
    }

    @Test func mtimeAbove2to53Survives() throws {
        let t: Int64 = (1 << 53) + 1  // not representable as a Double
        let m = try Metadata(name: "x", dir: "", mtime: t, mime: "", rev: 1, size: 0)
        #expect(try Metadata.parse(padded: m.paddedPlaintext()).mtime == t)
        #expect(Int64(Double(t)) != t)
    }

    @Test func slashWithCombiningMarkIsStillASlash() {
        // "/" + U+0301 is a single Swift Character that is not equal to "/".
        #expect(errorClass { _ = try Metadata(name: "a/\u{0301}b", dir: "", mtime: 0, mime: "", rev: 1, size: 0) } == "metadata")
        // Byte-wise this dir ends in "/" + U+0301 + "/", a trailing slash.
        #expect(errorClass { _ = try Metadata(name: "x", dir: "a/\u{0301}/", mtime: 0, mime: "", rev: 1, size: 0) } == "metadata")
        // A component that is only a combining mark is allowed.
        #expect(throws: Never.self) { _ = try Metadata(name: "x", dir: "a/\u{0301}", mtime: 0, mime: "", rev: 1, size: 0) }
    }

    @Test func readerDoesNotRequireNFC() throws {
        let nfd = Array("Ka\u{0308}".utf8)
        let m = Metadata(unchecked: nfd, [], 0, [], 1, 0)
        let back = try Metadata.parse(padded: m.paddedPlaintext())
        #expect(back.nameUTF8 == nfd)
        #expect(!back.isNFC)
    }

    @Test func strictReaderRejections() {
        let base = #"{"name":"a","dir":"","mtime":0,"mime":"","rev":1,"size":0}"#
        #expect(throws: Never.self) { _ = try Metadata.parse(padded: padded(base)) }
        let bad = [
            #"{"name":"a","dir":"","mtime":0,"mime":"","rev":1,"size":0 }"#,       // whitespace
            #"{"name":"a","dir":"","mtime":+1,"mime":"","rev":1,"size":0}"#,       // plus sign
            #"{"name":"a\n","dir":"","mtime":0,"mime":"","rev":1,"size":0}"#,      // \n escape
            #"{"name":"a\u000A","dir":"","mtime":0,"mime":"","rev":1,"size":0}"#,  // uppercase hex
            #"{"name":"a\u0020","dir":"","mtime":0,"mime":"","rev":1,"size":0}"#,  // needless escape
            "{\"name\":\"a\tb\",\"dir\":\"\",\"mtime\":0,\"mime\":\"\",\"rev\":1}",  // raw control
            #"{"name":"a","dir":"","mtime":0,"mime":"","rev":1,"size":0}x"#,       // trailing data
            #"{"name":"a","dir":"","mtime":0,"mime":""}"#,                // missing key
        ]
        for j in bad {
            #expect(errorClass { _ = try Metadata.parse(padded: padded(j)) } == "metadata", "\(j)")
        }
        #expect(errorClass { _ = try Metadata.parse(padded: [UInt8](repeating: 0x20, count: 512)) } == "metadata")
    }

    @Test func escapesRoundTrip() throws {
        let raw: [UInt8] = [0x00, 0x1F, 0x22, 0x5C, 0x7F, 0x2F]
        let m = try Metadata(nameUTF8: Array("n".utf8), dirUTF8: [], mtime: -1, mimeUTF8: raw, rev: 1, size: 0)
        let json = String(decoding: m.canonicalJSON(), as: UTF8.self)
        #expect(json.contains(#""mime":"\u0000\u001f\"\\"#))
        #expect(try Metadata.parse(padded: m.paddedPlaintext()) == m)
    }
}
