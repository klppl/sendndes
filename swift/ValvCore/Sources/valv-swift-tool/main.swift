// valv-swift-tool: a minimal interop test aid for ValvCore. Not the app.
// No safety features: no temp files, no outside-the-vault checks, no
// directory handles. The passphrase is read from stdin only (one line; a
// single trailing LF is removed).
//
//   valv-swift-tool decrypt-object <vault.json> <object-file> <out>
//   valv-swift-tool encrypt-object <vault.json> <in> <out-object> --name N --dir D
//   valv-swift-tool seal-inbox     <vault.json> <in> <out-inbox>  --name N --dir D
//   valv-swift-tool init           <vault-dir>
//   valv-swift-tool unlock         <vault.json>
//   valv-swift-tool show-meta      <vault.json> <object-file>
//   valv-swift-tool show-keys      <vault.json>     (only with --traits VALV_TESTVECTORS)
//
// encrypt-object and seal-inbox print the new file_id (32 hex) on stdout; the
// caller moves the file to objects/<xx>/<id>.obj or inbox/<id>.inb.
// The object file's path must end in <xx>/<id>.obj (the expected file_id).
// init writes vault.json and empty objects/ and inbox/, and prints nothing.
// show-meta prints the stored name and dir as UTF-8 hex.
// show-keys prints inbox_pub, k_auth and the recovery key; it exists only in
// builds with the test trait, so a normal build cannot print keys.
import Foundation
import ValvCore

func fail(_ msg: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("valv-swift-tool: \(msg)\n".utf8))
    exit(code)
}

let usage = """
    usage: valv-swift-tool decrypt-object <vault.json> <object-file> <out>
           valv-swift-tool encrypt-object <vault.json> <in> <out-object> --name N --dir D
           valv-swift-tool seal-inbox     <vault.json> <in> <out-inbox>  --name N --dir D
           valv-swift-tool init           <vault-dir>
           valv-swift-tool unlock         <vault.json>
           valv-swift-tool show-meta      <vault.json> <object-file>
    """

func wipe(_ b: inout [UInt8]) {
    b.withUnsafeMutableBytes { p in if let a = p.baseAddress { _ = memset_s(a, p.count, 0, p.count) } }
}

func readPassphrase() -> [UInt8] {
    var b = [UInt8](FileHandle.standardInput.readDataToEndOfFile())
    if b.last == 0x0A { b.removeLast() }
    return b
}

func unlock(_ vaultJSONPath: String) -> Vault {
    guard let json = FileManager.default.contents(atPath: vaultJSONPath) else { fail("cannot read \(vaultJSONPath)") }
    var pw = readPassphrase()
    defer { wipe(&pw) }
    do {
        return try Vault.unlock(vaultJSON: json, passphraseUTF8: pw)
    } catch {
        fail("\(error)")
    }
}

func openRead(_ path: String) -> FileHandle {
    guard let h = FileHandle(forReadingAtPath: path) else { fail("cannot open \(path)") }
    return h
}

func create(_ path: String) -> FileHandle {
    guard FileManager.default.createFile(atPath: path, contents: nil, attributes: [.posixPermissions: 0o600]),
          let h = FileHandle(forWritingAtPath: path) else { fail("cannot create \(path)") }
    return h
}

func hex(_ b: [UInt8]) -> String {
    b.map { String(format: "%02x", $0) }.joined()
}

/// Builds metadata from --name/--dir and the input file's mtime (ns).
func metadata(_ args: [String], input: String) -> Metadata {
    var name: String?
    var dir = ""
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--name" where i + 1 < args.count: name = args[i + 1]; i += 2
        case "--dir" where i + 1 < args.count: dir = args[i + 1]; i += 2
        default: fail("unknown argument \(args[i])\n\(usage)", 2)
        }
    }
    guard let name else { fail("--name is required", 2) }
    var st = stat()
    guard stat(input, &st) == 0 else { fail("cannot stat \(input)") }
    let (ns, o1) = Int64(st.st_mtimespec.tv_sec).multipliedReportingOverflow(by: 1_000_000_000)
    let (mtime, o2) = ns.addingReportingOverflow(Int64(st.st_mtimespec.tv_nsec))
    guard !o1, !o2 else { fail("mtime out of range") }
    do {
        // Metadata(name:dir:...) normalizes name and dir to NFC (SPEC 5.2).
        return try Metadata(name: name, dir: dir, mtime: mtime, mime: "", rev: 1)
    } catch {
        fail("\(error)")
    }
}

func args(_ argv: [String], _ n: Int) -> [String] {
    guard argv.count >= n + 1 else { fail(usage, 2) }
    return Array(argv[1...n])
}

let argv = Array(CommandLine.arguments.dropFirst())
guard let cmd = argv.first else { fail(usage, 2) }

switch cmd {
case "decrypt-object":
    let a = args(argv, 3)
    guard argv.count == 4 else { fail(usage, 2) }
    let vault = unlock(a[0])
    let out = create(a[2])
    do {
        let expected = try FileID(objectPath: a[1])
        try vault.decryptObject(FileInput(openRead(a[1])), expected: expected, to: FileOutput(out))
        try out.close()
    } catch {
        try? FileManager.default.removeItem(atPath: a[2])
        fail("\(error)")
    }

case "encrypt-object", "seal-inbox":
    let a = args(argv, 3)
    let meta = metadata(Array(argv.dropFirst(4)), input: a[1])
    let vault = unlock(a[0])
    let out = create(a[2])
    do {
        let input = FileInput(openRead(a[1]))
        let id = cmd == "encrypt-object"
            ? try vault.writeObject(plaintext: input, metadata: meta, to: FileOutput(out))
            : try vault.makeInboxSealer().seal(plaintext: input, metadata: meta, to: FileOutput(out))
        try out.close()
        print(id.hex)
    } catch {
        try? FileManager.default.removeItem(atPath: a[2])
        fail("\(error)")
    }

case "init":
    let a = args(argv, 1)
    guard argv.count == 2 else { fail(usage, 2) }
    let dir = URL(fileURLWithPath: a[0])
    guard !FileManager.default.fileExists(atPath: dir.path) else { fail("\(a[0]) already exists") }
    var pw = readPassphrase()
    defer { wipe(&pw) }
    guard let pass = String(bytes: pw, encoding: .utf8) else { fail("passphrase is not valid UTF-8") }
    do {
        let created = try Vault.create(passphrase: pass)
        let fm = FileManager.default
        let attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        try fm.createDirectory(at: dir, withIntermediateDirectories: false, attributes: attrs)
        try fm.createDirectory(at: dir.appendingPathComponent("objects"), withIntermediateDirectories: false, attributes: attrs)
        try fm.createDirectory(at: dir.appendingPathComponent("inbox"), withIntermediateDirectories: false, attributes: attrs)
        let json = dir.appendingPathComponent("vault.json").path
        guard fm.createFile(atPath: json, contents: created.vaultJSON, attributes: [.posixPermissions: 0o600]) else {
            fail("cannot write vault.json")
        }
        // Read back and unlock, as SPEC 4.3 init step 3 requires.
        guard let back = fm.contents(atPath: json) else { fail("cannot read back vault.json") }
        _ = try Vault.unlock(vaultJSON: back, passphrase: pass)
    } catch {
        fail("\(error)")
    }

case "unlock":
    let a = args(argv, 1)
    guard argv.count == 2 else { fail(usage, 2) }
    _ = unlock(a[0])
    print("unlocked")

case "show-meta":
    let a = args(argv, 2)
    guard argv.count == 3 else { fail(usage, 2) }
    let vault = unlock(a[0])
    do {
        let r = try vault.openObject(FileInput(openRead(a[1])), expected: FileID(objectPath: a[1]))
        try r.decryptAll(to: DiscardOutput())
        print("name_hex: \(hex(r.metadata.nameUTF8))")
        print("dir_hex: \(hex(r.metadata.dirUTF8))")
        print("nfc: \(r.metadata.isNFC)")
    } catch {
        fail("\(error)")
    }

#if VALV_TESTVECTORS
case "show-keys":
    let a = args(argv, 1)
    guard argv.count == 2 else { fail(usage, 2) }
    print(TestExports.keyReport(unlock(a[0])), terminator: "")
#endif

default:
    fail(usage, 2)
}
