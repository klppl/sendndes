import Foundation
import Testing
@testable import SenderCore

@Suite struct FileNameTests {
    private func clean(_ s: String?) -> String { FileNames.sanitize(s, fallback: "FALLBACK") }

    @Test func ordinaryNamesAreKept() {
        #expect(clean("IMG_0001.HEIC") == "IMG_0001.HEIC")
        #expect(clean("Räksmörgås 2026.pdf") == "Räksmörgås 2026.pdf")
        #expect(clean("한글.txt") == "한글.txt")
    }

    @Test func nfdBecomesNFC() {
        let nfd = "Ra\u{308}ksmo\u{308}rga\u{30A}s.txt"
        let out = clean(nfd)
        #expect(out == "Räksmörgås.txt")
        #expect(out.utf8.count < nfd.utf8.count)
    }

    @Test func slashesNulAndBackslashesNeverSurvive() {
        #expect(clean("a/b") == "a_b")
        #expect(clean("../../etc/passwd") == "_.._etc_passwd".replacingOccurrences(of: "_.._", with: "_.._"))
        for s in ["a/b", "a\\b", "a\0b", "/", "//", "../x"] {
            let o = clean(s)
            #expect(!o.contains("/") && !o.contains("\0") && !o.contains("\\") && o != "." && o != "..", "\(s)")
        }
    }

    @Test func dotsAndEmptyFallBack() {
        for s in [".", "..", "...", "", " ", "   ", "\u{202E}", "\n\t", nil] as [String?] { #expect(clean(s) == "FALLBACK", "\(String(describing: s))") }
        #expect(clean(".hidden") == "hidden")
        #expect(clean(" spaced name ") == "spaced name")
    }

    @Test func controlAndBidiCharactersAreRemoved() {
        #expect(clean("a\u{202E}gnp.exe") == "agnp.exe")
        #expect(clean("a\u{2066}b\u{2069}.txt") == "ab.txt")
        #expect(clean("a\u{200E}b\u{200F}") == "ab")
        #expect(clean("a\u{1}\u{7F}\u{85}b") == "ab")
        #expect(clean("a\u{0}b") == "a_b")
        #expect(clean("tab\tname\nline.txt") == "tabnameline.txt")
        #expect(clean("zero\u{200B}width\u{FEFF}.txt") == "zerowidth.txt")
    }

    @Test func longNamesAreCutOnACharacterAndKeepTheirExtension() {
        let long = String(repeating: "å", count: 300) + ".jpeg"
        let o = clean(long)
        #expect(o.utf8.count <= SenderLimits.maxNameBytes)
        #expect(o.hasSuffix(".jpeg"))
        #expect(String(validatingUTF8: o.cString(using: .utf8)!) == o)
        let noExt = clean(String(repeating: "x", count: 1000))
        #expect(noExt.utf8.count == SenderLimits.maxNameBytes)
        let emoji = clean(String(repeating: "👩‍👩‍👧", count: 80) + ".png")
        #expect(emoji.utf8.count <= SenderLimits.maxNameBytes)
    }

    @Test func manyCombiningMarksStillFitTheLimit() {
        let name = "a" + String(repeating: "\u{301}", count: 2000)
        #expect(clean(name).utf8.count <= SenderLimits.maxNameBytes)
        #expect(clean(String(repeating: "\u{301}", count: 2000) + "x").utf8.count <= SenderLimits.maxNameBytes)
    }

    @Test func moreInvisibleCharactersAreRemoved() {
        #expect(clean("a\u{2028}b\u{2029}c\u{AD}d\u{180E}e") == "abcde")
        #expect(clean("a\u{E0041}b") == "ab")
    }

    @Test func fallbackName() {
        let d = Date(timeIntervalSince1970: 1_792_310_400)
        #expect(FileNames.fallbackName(now: d, ext: "png").hasPrefix("shared-2026"))
        #expect(FileNames.fallbackName(now: d, ext: "png").hasSuffix(".png"))
        #expect(!FileNames.fallbackName(now: d, ext: "p/n g").contains("/"))
        #expect(!FileNames.fallbackName(now: d, ext: nil).contains("."))
    }

    @Test func folders() {
        #expect(FileNames.validateFolder("iPhone") == "iPhone")
        #expect(FileNames.validateFolder("Photos/2026") == "Photos/2026")
        #expect(FileNames.validateFolder("") == "")
        #expect(FileNames.validateFolder("  iPhone ") == "iPhone")
        for bad in ["a/ /b", "a/ b", "/a", "a/", "a//b", "a/../b", "./a", "..", ".", "a\\b", "a\0b", "a\u{202E}b", String(repeating: "x", count: 201)] {
            #expect(FileNames.validateFolder(bad) == nil, "\(bad)")
        }
        #expect(FileNames.validateFolder("Ko\u{308}k") == "Kök")
    }
}

@Suite struct SealerTests {
    func makeSealer(_ outbox: Outbox, folder: String = "iPhone") throws -> ShareSealer {
        ShareSealer(pairing: try pairing(), outbox: outbox, files: NoProtection(), folder: folder)
    }

    func file(_ dir: URL, _ name: String, _ data: Data) -> URL {
        let u = dir.appendingPathComponent(name)
        try! data.write(to: u)
        return u
    }

    @Test(arguments: [0, 1, 4095, 4096, 65535, 65536, 65537, 200_000])
    func sealedFileHasTheDocumentedShape(_ n: Int) throws {
        let dir = tempDir("seal")
        defer { try? FileManager.default.removeItem(at: dir) }
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        let src = file(dir, "photo.png", pattern(n))
        let item = try makeSealer(outbox).seal(fileAt: src, suggestedName: "photo.png")
        #expect(item.size == Int64(n) && item.state == .sealed && item.attempts == 0)
        let bytes = try Data(contentsOf: outbox.sealedURL(item.id))
        #expect(Int64(bytes.count) == item.sealedSize)
        #expect(Array(bytes.prefix(6)) == Array("NDES".utf8) + [2, 2], "magic, version 2, kind inbox")
        #expect(bytes.count > 58 + 540)
        // header (58 + meta_len) + padded content + one 16-byte tag per 64 KiB chunk
        let metaLen = Int(bytes[54]) << 24 | Int(bytes[55]) << 16 | Int(bytes[56]) << 8 | Int(bytes[57])
        let padded = paddedSize(n)
        #expect(bytes.count == 58 + metaLen + padded + 16 * ((padded + 65535) / 65536))
        // The plaintext does not appear in what was written.
        if n >= 64 { #expect(bytes.range(of: pattern(n).prefix(64)) == nil) }
        // The file id in the header is the item id and the file name.
        let idHex = bytes[6..<22].map { String(format: "%02x", $0) }.joined()
        #expect(idHex == item.id)
        // No stray temp files.
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.appendingPathComponent("outbox").path)
        #expect(!names.contains { $0.hasPrefix(".sealing-") })
    }

    @Test func eachSealGetsAFreshIDAndFreshBytes() throws {
        let dir = tempDir("seal2")
        defer { try? FileManager.default.removeItem(at: dir) }
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        let src = file(dir, "a.txt", Data("same".utf8))
        let a = try makeSealer(outbox).seal(fileAt: src, suggestedName: "a.txt")
        let b = try makeSealer(outbox).seal(fileAt: src, suggestedName: "a.txt")
        #expect(a.id != b.id)
        #expect(try Data(contentsOf: outbox.sealedURL(a.id)) != Data(contentsOf: outbox.sealedURL(b.id)))
    }

    @Test func overTheLimitIsRefusedBeforeAnythingIsWritten() throws {
        let dir = tempDir("seal3")
        defer { try? FileManager.default.removeItem(at: dir) }
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        // A sparse file of limit + 1 bytes.
        let u = dir.appendingPathComponent("big.bin")
        FileManager.default.createFile(atPath: u.path, contents: nil)
        let h = try FileHandle(forWritingTo: u)
        try h.truncate(atOffset: UInt64(SenderLimits.maxFileBytes + 1)); try h.close()
        #expect(throws: SealError.tooLarge(SenderLimits.maxFileBytes + 1)) { try makeSealer(outbox).seal(fileAt: u, suggestedName: "big.bin") }
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.appendingPathComponent("outbox").path).isEmpty)
    }

    @Test func aFileThatGrowsWhileItIsSealedIsRefusedAndLeavesNothing() throws {
        let dir = tempDir("seal4")
        defer { try? FileManager.default.removeItem(at: dir) }
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        let src = file(dir, "grow.bin", pattern(100_000))
        let sealer = try makeSealer(outbox)
        let (fd, cand) = try ShareSealer.inspect(src)
        // Someone appends after we looked at the size.
        let h = try FileHandle(forWritingTo: src); try h.seekToEnd(); try h.write(contentsOf: pattern(5000)); try h.close()
        #expect(throws: SealError.fileChanged) { try sealer.sealOpened(fd: fd, candidate: cand, url: src, suggestedName: "grow.bin", mime: nil) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.appendingPathComponent("outbox").path).isEmpty)
        #expect(outbox.items().isEmpty)
    }

    @Test func aFileThatShrinksIsRefusedToo() throws {
        let dir = tempDir("seal5")
        defer { try? FileManager.default.removeItem(at: dir) }
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        let src = file(dir, "shrink.bin", pattern(100_000))
        let sealer = try makeSealer(outbox)
        let (fd, cand) = try ShareSealer.inspect(src)
        let h = try FileHandle(forWritingTo: src); try h.truncate(atOffset: 10); try h.close()
        #expect(throws: SealError.fileChanged) { try sealer.sealOpened(fd: fd, candidate: cand, url: src, suggestedName: "shrink.bin", mime: nil) }
        #expect(outbox.items().isEmpty)
    }

    @Test func symlinksDirectoriesAndMissingFilesAreRefused() throws {
        let dir = tempDir("seal6")
        defer { try? FileManager.default.removeItem(at: dir) }
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        let real = file(dir, "real.txt", Data("x".utf8))
        let link = dir.appendingPathComponent("link.txt")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        let sealer = try makeSealer(outbox)
        #expect(throws: SealError.notARegularFile) { try sealer.seal(fileAt: link, suggestedName: "link.txt") }
        #expect(throws: SealError.notARegularFile) { try sealer.seal(fileAt: dir, suggestedName: "dir") }
        #expect(throws: SealError.cannotRead) { try sealer.seal(fileAt: dir.appendingPathComponent("nope"), suggestedName: "nope") }
        #expect(throws: SealError.notARegularFile) { try sealer.seal(fileAt: URL(fileURLWithPath: "/dev/zero"), suggestedName: "zero") }
        #expect(outbox.items().isEmpty)
    }

    @Test func aFIFOIsRefusedWithoutHanging() throws {
        let dir = tempDir("fifo")
        defer { try? FileManager.default.removeItem(at: dir) }
        let fifo = dir.appendingPathComponent("pipe")
        #expect(mkfifo(fifo.path, 0o600) == 0)
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        #expect(throws: SealError.notARegularFile) { try makeSealer(outbox).seal(fileAt: fifo, suggestedName: "pipe") }
    }

    @Test func aBadFolderIsRefused() throws {
        let dir = tempDir("seal7")
        defer { try? FileManager.default.removeItem(at: dir) }
        let outbox = try Outbox(directory: dir.appendingPathComponent("outbox"))
        let src = file(dir, "a.txt", Data("x".utf8))
        #expect(throws: SealError.badFolder) { try makeSealer(outbox, folder: "../x").seal(fileAt: src, suggestedName: "a.txt") }
    }

    @Test func guardedInputStopsAtTheDeclaredSizePlusOneProbe() throws {
        let g = GuardedInput(DataInputShim(Data(repeating: 1, count: 1000)), declared: 10, limit: 100)
        #expect(try g.read(upTo: 4).count == 4)
        #expect(try g.read(upTo: 100).count == 7, "10 declared + 1 probe, minus the 4 already read")
        #expect(throws: SealError.fileChanged) { try g.read(upTo: 1) }
        // The declared size can never exceed the limit.
        let h = GuardedInput(DataInputShim(Data(repeating: 1, count: 1000)), declared: 5000, limit: 100)
        #expect(try h.read(upTo: 1000).count == 101)
        #expect(throws: SealError.fileChanged) { try h.read(upTo: 1) }
    }
}
