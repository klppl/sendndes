// valv-swift-tool: a minimal interop test aid for ValvCore. Not the app.
// No safety features: no temp files, no outside-the-vault checks, no
// directory handles. The passphrase is read from stdin only (one line; a
// single trailing LF is removed).
//
//   valv-swift-tool decrypt-object <vault.json> <object-file> <out>
//   valv-swift-tool encrypt-object <vault.json> <in> <out-object> --name N --dir D
//   valv-swift-tool seal-inbox     <vault.json> <in> <out-inbox>  --name N --dir D
//
// encrypt-object and seal-inbox print the new file_id (32 hex) on stdout; the
// caller moves the file to objects/<xx>/<id>.obj or inbox/<id>.inb.
// The object file's path must end in <xx>/<id>.obj (the expected file_id).
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
    """

func readPassphrase() -> [UInt8] {
    var b = [UInt8](FileHandle.standardInput.readDataToEndOfFile())
    if b.last == 0x0A { b.removeLast() }
    return b
}

func unlock(_ vaultJSONPath: String) -> Vault {
    guard let json = FileManager.default.contents(atPath: vaultJSONPath) else { fail("cannot read \(vaultJSONPath)") }
    var pw = readPassphrase()
    defer { pw.withUnsafeMutableBytes { p in if let a = p.baseAddress { _ = memset_s(a, p.count, 0, p.count) } } }
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
        return try Metadata(name: name, dir: dir, mtime: mtime, mime: "", rev: 1)
    } catch {
        fail("\(error)")
    }
}

let argv = Array(CommandLine.arguments.dropFirst())
guard argv.count >= 4 else { fail(usage, 2) }
let (cmd, vaultJSON, inPath, outPath) = (argv[0], argv[1], argv[2], argv[3])
let rest = Array(argv.dropFirst(4))

switch cmd {
case "decrypt-object":
    guard rest.isEmpty else { fail(usage, 2) }
    let vault = unlock(vaultJSON)
    let out = create(outPath)
    do {
        let expected = try FileID(objectPath: inPath)
        try vault.decryptObject(FileInput(openRead(inPath)), expected: expected, to: FileOutput(out))
        try out.close()
    } catch {
        try? FileManager.default.removeItem(atPath: outPath)
        fail("\(error)")
    }

case "encrypt-object", "seal-inbox":
    let meta = metadata(rest, input: inPath)
    let vault = unlock(vaultJSON)
    let out = create(outPath)
    do {
        let input = FileInput(openRead(inPath))
        let id = cmd == "encrypt-object"
            ? try vault.writeObject(plaintext: input, metadata: meta, to: FileOutput(out))
            : try vault.makeInboxSealer().seal(plaintext: input, metadata: meta, to: FileOutput(out))
        try out.close()
        print(id.hex)
    } catch {
        try? FileManager.default.removeItem(atPath: outPath)
        fail("\(error)")
    }

default:
    fail(usage, 2)
}
