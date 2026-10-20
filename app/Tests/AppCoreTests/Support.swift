import Foundation
import XCTest
import CryptoKit
@testable import AppCore

final class MemorySecrets: SecretStoring {
    var value: String?
    var server: String?
    func credential() -> StoredCredential? { value.map { StoredCredential(token: $0, server: server) } }
    func setCredential(token: String, server: String) throws { value = token; self.server = server }
    func deleteToken() { value = nil; server = nil }
}

final class MemoryBiometric: BiometricUnlocking {
    var isAvailable = true
    var saved: [String: String] = [:]
    func hasPassphrase(vault: String) -> Bool { saved[vault] != nil }
    func save(passphrase: String, vault: String) throws { saved[vault] = passphrase }
    func load(vault: String, reason: String) async -> String? { saved[vault] }
    func remove(vault: String) { saved[vault] = nil }
}

struct ToolResult { var status: Int32; var out: Data; var err: Data }

/// Runs a tool directly (test setup and checks only; the app itself uses HelperRunner).
@discardableResult
func runTool(_ path: String, _ args: [String], stdin: String = "") -> ToolResult {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let i = Pipe(), o = Pipe(), e = Pipe()
    p.standardInput = i; p.standardOutput = o; p.standardError = e
    try! p.run()
    i.fileHandleForWriting.write(Data(stdin.utf8))
    try? i.fileHandleForWriting.close()
    var out = Data(), err = Data()
    let g = DispatchGroup()
    g.enter(); DispatchQueue.global().async { out = o.fileHandleForReading.readDataToEndOfFile(); g.leave() }
    g.enter(); DispatchQueue.global().async { err = e.fileHandleForReading.readDataToEndOfFile(); g.leave() }
    p.waitUntilExit(); g.wait()
    return ToolResult(status: p.terminationStatus, out: out, err: err)
}

func sha256Hex(of path: String) -> String {
    SHA256.hash(data: try! Data(contentsOf: URL(fileURLWithPath: path))).map { String(format: "%02x", $0) }.joined()
}

private let tempLock = NSLock()
nonisolated(unsafe) private var tempPaths: [String] = []
/// Removes every directory `realTemp()` made when the test process exits (Info: no sendndes-test-* leftovers).
private let installExitCleanup: Void = {
    atexit {
        tempLock.lock()
        for p in tempPaths { try? FileManager.default.removeItem(atPath: p) }
        tempLock.unlock()
    }
}()

func realTemp() -> String {
    _ = installExitCleanup
    var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
    let base = NSTemporaryDirectory() + "sendndes-test-" + UUID().uuidString
    try! FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    precondition(realpath(base, &buf) != nil)
    tempLock.lock(); tempPaths.append(String(cString: buf)); tempLock.unlock()
    return String(cString: buf)
}

func freePort() -> Int {
    let s = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(s) }
    var a = sockaddr_in()
    a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = 0
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = bind(s, $0, len) } }
    withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(s, $0, &len) } }
    return Int(UInt16(bigEndian: a.sin_port))
}

func portOpen(_ port: Int) -> Bool {
    let s = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(s) }
    var a = sockaddr_in()
    a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = UInt16(port).bigEndian
    return withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } == 0
}

let passphrase = "correct-horse-battery"
let goodToken = "0123456789abcdef0123456789abcdef-test-token"

/// A throwaway vault, a loopback valvd, the real helper copied next to it, and an AppModel wired to them.
@MainActor
final class Env {
    let tmp = realTemp()
    let binDir: String
    let helper: String
    let vault: String
    let inbox: String
    let tokenBase: String
    let port = freePort()
    var server: Process?
    let secrets = MemorySecrets()
    let biometric = MemoryBiometric()
    let runner: HelperRunner
    let model: AppModel
    let defaultsName = "sendndes-test-" + UUID().uuidString

    init(maxUploadBytes: Int64 = 64 << 20, startServer: Bool = true, serverArgs: [String] = []) throws {
        guard let bin = ProcessInfo.processInfo.environment["VALV_TEST_BIN"] else {
            throw XCTSkip("VALV_TEST_BIN not set; run scripts/test-app.sh")
        }
        binDir = bin
        try FileManager.default.createDirectory(atPath: tmp + "/helper", withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        helper = tmp + "/helper/valv"
        try FileManager.default.copyItem(atPath: bin + "/valv", toPath: helper)
        chmod(helper, 0o755)
        vault = tmp + "/vault"
        inbox = tmp + "/inbox"
        tokenBase = tmp + "/tokens"
        for d in [inbox, tokenBase] { try FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
        let ini = runTool(helper, ["init", vault, "--passphrase-stdin", "--allow-weak-passphrase"], stdin: passphrase + "\n")
        XCTAssertEqual(ini.status, 0, String(decoding: ini.err, as: UTF8.self))
        let cfg = runTool(helper, ["server-config", "--vault=\(vault)", "--passphrase-stdin"], stdin: passphrase + "\n")
        XCTAssertEqual(cfg.status, 0)
        FileManager.default.createFile(atPath: tmp + "/server.conf", contents: cfg.out, attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: tmp + "/valvd.token", contents: Data((goodToken + "\n").utf8), attributes: [.posixPermissions: 0o600])
        runner = HelperRunner(helperPath: helper, expectedSHA256: sha256Hex(of: helper))
        let suite = UserDefaults(suiteName: defaultsName)!
        suite.set("http://127.0.0.1:\(port)", forKey: AppModel.urlKey)
        suite.set(vault, forKey: AppModel.vaultKey)
        secrets.value = goodToken
        secrets.server = "http://127.0.0.1:\(port)"
        model = AppModel(defaults: suite, secrets: secrets, runner: runner, biometric: biometric, tempBase: tokenBase)
        if startServer { try startServerProcess(maxUploadBytes: maxUploadBytes, extraArgs: serverArgs) }
    }

    func startServerProcess(maxUploadBytes: Int64 = 64 << 20, extraArgs: [String] = []) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: binDir + "/valvd")
        p.arguments = ["--config", tmp + "/server.conf", "--token-file", tmp + "/valvd.token", "--inbox", inbox,
                       "--listen", "127.0.0.1:\(port)", "--max-upload-bytes", String(maxUploadBytes)] + extraArgs
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        server = p
        for _ in 0..<100 { if portOpen(port) { return }; Thread.sleep(forTimeInterval: 0.05) }
        XCTFail("valvd did not start")
    }

    func stopServer() { server?.terminate(); server?.waitUntilExit(); server = nil }

    func teardown() {
        stopServer()
        UserDefaults.standard.removePersistentDomain(forName: defaultsName)
        try? FileManager.default.removeItem(atPath: tmp)
    }

    var inboxFiles: [String] { ((try? FileManager.default.contentsOfDirectory(atPath: inbox)) ?? []).filter { $0.hasSuffix(".inb") } }
    var tokenDirs: [String] { (try? FileManager.default.contentsOfDirectory(atPath: tokenBase)) ?? [] }

    func writeSource(_ name: String, _ bytes: Data) -> URL {
        let d = tmp + "/src"
        try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        let u = URL(fileURLWithPath: d + "/" + name)
        try! bytes.write(to: u)
        return u
    }

    func unlock() async { await model.unlock(passphrase: passphrase) }
}

/// A one-shot-per-connection fake HTTP server for hostile responses.
final class FakeServer: @unchecked Sendable {
    let port: Int
    private let listenFD: Int32
    private let lock = NSLock()
    private(set) var requestLines: [String] = []
    private(set) var bytesWritten = 0
    private(set) var lastHead = ""        // request headers of the latest request
    private(set) var lastBodyPrefix = Data() // body bytes that arrived together with the headers
    private var stop = false

    /// `respond` gets the connected fd after the request headers were read.
    init(respond: @escaping @Sendable (Int32, FakeServer) -> Void) {
        port = freePort()
        listenFD = socket(AF_INET, SOCK_STREAM, 0)
        var one: Int32 = 1
        setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &one, 4)
        var a = sockaddr_in()
        a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = UInt16(port).bigEndian
        withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        listen(listenFD, 8)
        let fd = listenFD
        DispatchQueue.global().async { [unowned self] in
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { return }
                var on: Int32 = 1
                setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &on, 4)
                DispatchQueue.global().async {
                    var buf = [UInt8](repeating: 0, count: 8192)
                    var head = Data()
                    while !head.range(of: Data("\r\n\r\n".utf8)).map({ _ in true }, default: false) {
                        let n = read(c, &buf, buf.count)
                        if n <= 0 { close(c); return }
                        head.append(contentsOf: buf[0..<n])
                    }
                    self.lock.lock()
                    self.requestLines.append(String(decoding: head.prefix(while: { $0 != 0x0D }), as: UTF8.self))
                    if let r = head.range(of: Data("\r\n\r\n".utf8)) {
                        self.lastHead = String(decoding: head[..<r.lowerBound], as: UTF8.self)
                        self.lastBodyPrefix = Data(head[r.upperBound...])
                    }
                    self.lock.unlock()
                    respond(c, self)
                    close(c)
                }
            }
        }
    }

    func write(_ fd: Int32, _ s: String) { write(fd, Array(s.utf8)) }
    @discardableResult func write(_ fd: Int32, _ b: [UInt8]) -> Bool {
        var off = 0
        while off < b.count {
            let n = b.withUnsafeBytes { Foundation.write(fd, $0.baseAddress! + off, b.count - off) }
            if n <= 0 { return false }
            off += n
            lock.lock(); bytesWritten += n; lock.unlock()
        }
        return true
    }
    var requests: [String] { lock.lock(); defer { lock.unlock() }; return requestLines }
    var written: Int { lock.lock(); defer { lock.unlock() }; return bytesWritten }
    func shutdown() { close(listenFD) }
}

extension Optional {
    func map<T>(_ f: (Wrapped) -> T, default d: T) -> T { self.map(f) ?? d }
}
