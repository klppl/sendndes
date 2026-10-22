import CryptoKit
import Foundation
import Testing
@testable import SenderCore

/// SenderCore against the real `ndesd` (loopback) and the real `ndes`: seal on the "phone", upload, pull, get.
/// Needs NDES_TEST_BIN (a folder with `ndes` and `ndesd`); `scripts/build-ios.sh` sets it up. Skipped otherwise.
final class Env: @unchecked Sendable {
    let bin: String
    let dir: URL
    let vault: URL
    let inbox: URL
    let port: Int
    let pass = "correct horse battery staple"
    var server: Process?
    let pairing: Pairing
    let uploadToken: String
    let pullTokenFile: URL
    var ownerToken: String { (try? String(contentsOf: pullTokenFile, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "" }
    let tokensLine: String

    init?(pairing wantsPairing: Bool = false) throws {
        guard let b = ProcessInfo.processInfo.environment["NDES_TEST_BIN"] else { return nil }
        bin = b
        dir = tempDir("integ")
        vault = dir.appendingPathComponent("vault")
        inbox = dir.appendingPathComponent("inbox")
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        port = Int.random(in: 20000..<40000)
        try Self.run(b + "/ndes", ["init", vault.path, "--passphrase-stdin", "--allow-weak-passphrase"], stdin: pass + "\n").ok()
        let sc = try Self.run(b + "/ndes", ["sender-config", "--vault", vault.path, "--passphrase-stdin", "--server", "https://inbox.example.com", "--label", "iphone-1"], stdin: pass + "\n").ok()
        var fields: [String: String] = [:]
        for l in sc.out.split(separator: "\n") { let p = l.split(separator: ":", maxSplits: 1); if p.count == 2 { fields[String(p[0])] = p[1].trimmingCharacters(in: .whitespaces) } }
        let payload = try SenderPayload.parse(fields["payload"]!)
        // The same keys and token, but pointed at the loopback server (https is not available here).
        pairing = Pairing(server: try ServerURL.parseForTests("http://127.0.0.1:\(port)"), label: payload.label, fingerprint: payload.fingerprint,
                          inboxPub: payload.inboxPub, kAuth: payload.kAuth, token: payload.token!)
        uploadToken = payload.token!
        tokensLine = fields["token-line"]!
        // A pull token for the Mac side.
        let mac = b64url(Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
        pullTokenFile = dir.appendingPathComponent("mac.token")
        try Data((mac + "\n").utf8).write(to: pullTokenFile)
        chmod(pullTokenFile.path, 0o600)
        let macHash = SHA256.hash(data: Data(mac.utf8)).map { String(format: "%02x", $0) }.joined()
        let tokensFile = dir.appendingPathComponent("tokens")
        try Data((tokensLine + "\nboth mac " + macHash + "\n").utf8).write(to: tokensFile)
        chmod(tokensFile.path, 0o600)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: b + "/ndesd")
        p.arguments = ["--tokens-file", tokensFile.path, "--inbox", inbox.path, "--listen", "127.0.0.1:\(port)"]
            + (wantsPairing ? ["--pairing", "--pairing-open-minutes", "5"] : [])
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        server = p
        for _ in 0..<100 {
            if let s = try? Self.connect(port) { close(s); break }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    deinit { server?.terminate(); server?.waitUntilExit(); try? FileManager.default.removeItem(at: dir) }

    static func connect(_ port: Int) throws -> Int32 {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_port = in_port_t(port).bigEndian; a.sin_addr.s_addr = inet_addr("127.0.0.1")
        let r = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard r == 0 else { close(s); throw SealError.cannotRead }
        return s
    }

    struct Result { let status: Int32; let out: String; let err: String
        @discardableResult func ok() throws -> Result { if status != 0 { throw NSError(domain: "run", code: Int(status), userInfo: [NSLocalizedDescriptionKey: err]) }; return self } }

    static func run(_ exe: String, _ args: [String], stdin: String = "") throws -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
        p.environment = ["PATH": "/usr/bin:/bin"]
        let i = Pipe(), o = Pipe(), e = Pipe()
        p.standardInput = i; p.standardOutput = o; p.standardError = e
        try p.run()
        i.fileHandleForWriting.write(Data(stdin.utf8)); try i.fileHandleForWriting.close()
        let od = o.fileHandleForReading.readDataToEndOfFile(), ed = e.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Result(status: p.terminationStatus, out: String(decoding: od, as: UTF8.self), err: String(decoding: ed, as: UTF8.self))
    }

    func ndes(_ args: [String]) throws -> Result {
        try Self.run(bin + "/ndes", args + ["--vault", vault.path, "--passphrase-stdin"], stdin: pass + "\n")
    }

    /// PUT the sealed file like the app's transport does, and record the answer in the outbox.
    func upload(_ item: SealedItem, outbox: Outbox, token: String? = nil) async throws -> Int {
        guard let req = UploadRequest.make(server: pairing.server, id: item.id, token: token ?? uploadToken, length: item.sealedSize) else { throw SealError.sealingFailed }
        let cfg = URLSessionConfiguration.ephemeral
        let (data, resp) = try await URLSession(configuration: cfg).upload(for: req, fromFile: outbox.sealedURL(item.id))
        let status = (resp as! HTTPURLResponse).statusCode
        outbox.apply(.classify(status: status, body: data, forID: item.id), to: item.id)
        return status
    }
}

@Suite(.serialized) struct IntegrationTests {
    /// A phone pairs by approval: a code on the phone, the same code for the owner, approve, token arrives once.
    @Test func aPhonePairsByApprovalAgainstARealServer() async throws {
        guard let env = try Env(pairing: true) else { return }
        // The Mac makes a pairing code (no token inside).
        let sc = try Env.run(env.bin + "/ndes", ["sender-config", "--pair", "--vault", env.vault.path, "--passphrase-stdin", "--server", "https://inbox.example.com", "--label", "iphone-x"], stdin: env.pass + "\n").ok()
        let payloadLine = try #require(sc.out.split(separator: "\n").first { $0.hasPrefix("payload: ") }).dropFirst(9)
        let payload = try SenderPayload.parse(String(payloadLine))
        #expect(payload.token == nil && payload.label == "iphone-x")
        let server = env.pairing.server   // the loopback address stands in for the https one
        guard case .success(let req) = await PairClient.request(server: server, label: payload.label) else { Issue.record("request refused"); return }
        #expect(req.code.count == 6)
        // The owner sees the same code and approves.
        func owner(_ method: String, _ path: String) async throws -> (Int, Data) {
            var r = URLRequest(url: URL(string: server.canonical + path)!)
            r.httpMethod = method
            r.setValue("Bearer " + env.ownerToken, forHTTPHeaderField: "Authorization")
            let (d, resp) = try await URLSession.shared.data(for: r)
            return ((resp as! HTTPURLResponse).statusCode, d)
        }
        let (c1, pending) = try await owner("GET", "/v1/pair/pending")
        #expect(c1 == 200 && String(decoding: pending, as: UTF8.self).contains(req.code))
        guard case .success(.pending) = await PairClient.status(server: server, request: req) else { Issue.record("not pending"); return }
        #expect(try await owner("POST", "/v1/pair/\(req.id)/approve").0 == 200)
        guard case .success(.approved(let token)) = await PairClient.status(server: server, request: req) else { Issue.record("not approved"); return }
        #expect(token.count == 43)
        // The token works for uploading and for nothing else, and is released only once.
        var ping = UploadRequest.ping(server: server, token: token)!
        ping.timeoutInterval = 10
        #expect(((try await URLSession.shared.data(for: ping)).1 as! HTTPURLResponse).statusCode == 204)
        var list = URLRequest(url: URL(string: server.canonical + "/inbox")!)
        list.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        #expect(((try await URLSession.shared.data(for: list)).1 as! HTTPURLResponse).statusCode == 403)
        if case .success = await PairClient.status(server: server, request: req) { Issue.record("the token was released twice") }
        // Save it like the app does, and the phone can seal and upload.
        let store = PairingStore(directory: env.dir.appendingPathComponent("cfg"), secrets: MemorySecrets())
        try store.save(payload.withToken(token))
        #expect(store.load()?.token == token)
    }

    @Test func swiftSealedFilesArePulledAndReadBackByteIdentical() async throws {
        guard let env = try Env() else { return }
        let outbox = try Outbox(directory: env.dir.appendingPathComponent("outbox"))
        let sealer = ShareSealer(pairing: env.pairing, outbox: outbox, folder: "iPhone")
        var expected: [String: Data] = [:]
        for n in [0, 1, 4096, 65536, 200_000] {
            let src = env.dir.appendingPathComponent("src-\(n)")
            let data = pattern(n, seed: UInt8(n % 251))
            try data.write(to: src)
            let item = try sealer.seal(fileAt: src, suggestedName: "f-\(n).bin")
            expected["iPhone/f-\(n).bin"] = data
            let status = try await env.upload(item, outbox: outbox)
            #expect(status == 201, "size \(n)")
            #expect(outbox.item(item.id) == nil, "stored items leave the outbox")
        }
        // The server directory holds only sealed .inb files.
        let names = try FileManager.default.contentsOfDirectory(atPath: env.inbox.path)
        #expect(names.count == 5 && names.allSatisfy { $0.hasSuffix(".inb") && $0.count == 36 }, "\(names)")

        let src = env.dir.appendingPathComponent("again")
        try pattern(777).write(to: src)
        let item = try sealer.seal(fileAt: src, suggestedName: "again.bin")
        #expect(try await env.upload(item, outbox: outbox) == 201)
        expected["iPhone/again.bin"] = pattern(777)

        // The Mac side pulls, ingests, and returns every file byte for byte.
        let pull = try Env.run(env.bin + "/ndes", ["pull", "--vault", env.vault.path, "--passphrase-stdin", "--server", "http://127.0.0.1:\(env.port)",
                                                    "--token-file", env.pullTokenFile.path], stdin: env.pass + "\n").ok()
        #expect(pull.out.contains("ingested 6") || pull.err.contains("ingested 6") , "\(pull.out) \(pull.err)")
        for (path, data) in expected {
            let out = env.dir.appendingPathComponent("out-" + path.replacingOccurrences(of: "/", with: "_"))
            try env.ndes(["get", path, "-o", out.path]).ok()
            #expect(try Data(contentsOf: out) == data, Comment(rawValue: path))
        }
        let verify = try env.ndes(["verify"]).ok()
        #expect(verify.out.contains("0 problem(s)"), Comment(rawValue: verify.out))
        // The server's inbox is empty again after the pull deleted what it ingested.
        #expect(try FileManager.default.contentsOfDirectory(atPath: env.inbox.path).isEmpty)
    }

    @Test func retryOfAStoredIdAnswers200AndAWrongTokenIs401() async throws {
        guard let env = try Env() else { return }
        let outbox = try Outbox(directory: env.dir.appendingPathComponent("outbox"))
        let sealer = ShareSealer(pairing: env.pairing, outbox: outbox, folder: "iPhone")
        let src = env.dir.appendingPathComponent("x"); try pattern(5000).write(to: src)
        let item = try sealer.seal(fileAt: src, suggestedName: "x.bin")
        let keep = env.dir.appendingPathComponent("copy.inb")
        try FileManager.default.copyItem(at: outbox.sealedURL(item.id), to: keep)
        #expect(try await env.upload(item, outbox: outbox, token: "wrong-token-wrong-token-wrong-token-1234") == 401)
        #expect(outbox.item(item.id)?.failure == .tokenRejected)
        #expect(outbox.retry(item.id))
        #expect(try await env.upload(item, outbox: outbox) == 201)
        // Replay the same bytes under the same id: the server says it is already stored.
        try FileManager.default.copyItem(at: keep, to: outbox.sealedURL(item.id))
        _ = try outbox.add(id: item.id, displayName: "x.bin", size: item.size, sealedSize: item.sealedSize)
        #expect(try await env.upload(item, outbox: outbox) == 200)
        #expect(try FileManager.default.contentsOfDirectory(atPath: env.inbox.path).count == 1)
        // An upload token cannot list, read or delete.
        var r = URLRequest(url: URL(string: "http://127.0.0.1:\(env.port)/inbox")!)
        r.setValue("Bearer " + env.uploadToken, forHTTPHeaderField: "Authorization")
        let (_, resp) = try await URLSession.shared.data(for: r)
        #expect((resp as! HTTPURLResponse).statusCode == 403)
        // Ping works for the phone's token.
        let ping = UploadRequest.ping(server: env.pairing.server, token: env.uploadToken)!
        let (_, pr) = try await URLSession.shared.data(for: ping)
        #expect((pr as! HTTPURLResponse).statusCode == 204)
    }

    private static func peakRSS() -> Int {
        var u = rusage(); getrusage(RUSAGE_SELF, &u)
        return Int(u.ru_maxrss) // bytes on macOS
    }

    @Test func ninetyMiBSealsWithFlatMemoryAndSurvivesTheRoundTrip() async throws {
        guard let env = try Env() else { return }
        let outbox = try Outbox(directory: env.dir.appendingPathComponent("outbox"))
        let sealer = ShareSealer(pairing: env.pairing, outbox: outbox, folder: "iPhone")
        let src = env.dir.appendingPathComponent("big.bin")
        FileManager.default.createFile(atPath: src.path, contents: nil)
        let h = try FileHandle(forWritingTo: src)
        let chunk = pattern(1 << 20, seed: 9)
        for _ in 0..<90 { try h.write(contentsOf: chunk) }   // exactly 90 MiB
        try h.close()
        #expect(try FileManager.default.attributesOfItem(atPath: src.path)[.size] as? Int == 90 << 20)
        let before = Self.peakRSS()
        let item = try sealer.seal(fileAt: src, suggestedName: "big.bin")
        let growth = Self.peakRSS() - before
        #expect(growth < 40 << 20, Comment(rawValue: "sealing 90 MiB grew peak memory by \(growth >> 20) MiB"))
        #expect(item.sealedSize < 100_000_000)
        #expect(item.sealedSize <= 95_420_416, "fits the server's --max-sealed-bytes default")
        #expect(try await env.upload(item, outbox: outbox) == 201)
        try Env.run(env.bin + "/ndes", ["pull", "--vault", env.vault.path, "--passphrase-stdin", "--server", "http://127.0.0.1:\(env.port)",
                                         "--token-file", env.pullTokenFile.path], stdin: env.pass + "\n").ok()
        let out = env.dir.appendingPathComponent("big-out")
        try env.ndes(["get", "iPhone/big.bin", "-o", out.path]).ok()
        let sum = try Env.run("/usr/bin/shasum", ["-a", "256", out.path]).ok().out.split(separator: " ").first.map(String.init)
        let want = try Env.run("/usr/bin/shasum", ["-a", "256", src.path]).ok().out.split(separator: " ").first.map(String.init)
        #expect(sum == want && sum != nil)
    }

    @Test func overTheLimitIsRefusedAndNothingIsUploaded() async throws {
        guard let env = try Env() else { return }
        let outbox = try Outbox(directory: env.dir.appendingPathComponent("outbox"))
        let sealer = ShareSealer(pairing: env.pairing, outbox: outbox, folder: "iPhone")
        let src = env.dir.appendingPathComponent("huge.bin")
        FileManager.default.createFile(atPath: src.path, contents: nil)
        let h = try FileHandle(forWritingTo: src); try h.truncate(atOffset: UInt64(SenderLimits.maxFileBytes + 1)); try h.close()
        #expect(throws: SealError.tooLarge(SenderLimits.maxFileBytes + 1)) { try sealer.seal(fileAt: src, suggestedName: "huge.bin") }
        #expect(outbox.items().isEmpty)
        #expect(try FileManager.default.contentsOfDirectory(atPath: env.inbox.path).isEmpty)
    }
}
