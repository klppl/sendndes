import Foundation
import NdesCore
import CryptoKit

let vkHex = "c660972aac797376ea9f855d87b834a1e8abf74fa2cb8940db2e92bfc5ea1ed4"
func hexDecode(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    let chars = Array(s.utf8)
    var i = 0
    while i < chars.count {
        func val(_ c: UInt8) -> UInt8 {
            if c >= 48 && c <= 57 { return c - 48 }
            if c >= 97 && c <= 102 { return c - 97 + 10 }
            if c >= 65 && c <= 70 { return c - 65 + 10 }
            return 0
        }
        out.append((val(chars[i]) << 4) | val(chars[i+1]))
        i += 2
    }
    return out
}

let testVK = hexDecode(vkHex)
let vault = try! Vault(vk: testVK)

let stdin = FileHandle.standardInput
let stdout = FileHandle.standardOutput

func readExact(_ n: Int) -> Data? {
    var d = Data()
    while d.count < n {
        guard let chunk = try? stdin.read(upToCount: n - d.count), !chunk.isEmpty else {
            return nil
        }
        d.append(chunk)
    }
    return d
}

func sendReply(status: UInt8, payload: Data) {
    var header = Data([status])
    var len = UInt32(payload.count).bigEndian
    withUnsafeBytes(of: &len) { header.append(contentsOf: $0) }
    try! stdout.write(contentsOf: header)
    if !payload.isEmpty {
        try! stdout.write(contentsOf: payload)
    }
}

func sendSuccess(_ payload: Data) {
    sendReply(status: 0, payload: payload)
}

func sendError(_ err: Error) {
    let errClass: String
    if let ve = err as? NdesError {
        errClass = ve.vectorClass
    } else {
        errClass = "malformed"
    }
    sendReply(status: 1, payload: Data(errClass.utf8))
}

func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

func fileIDFromBytes(_ raw: [UInt8]) throws -> FileID {
    guard raw.count == 16 else { throw NdesError.path("file_id must be 16 bytes") }
    let h = raw.map { String(format: "%02x", $0) }.joined()
    return try FileID(objectPath: "objects/\(h.prefix(2))/\(h).obj")
}

func metaSummary(_ m: Metadata) -> Data {
    let s = "\(m.name)|\(m.dir)|\(m.mtime)|\(m.mime)|\(m.rev)|\(m.size)"
    return sha256(Data(s.utf8))
}

while true {
    guard let cmdData = readExact(1) else { break }
    let cmd = cmdData[0]
    guard let lenData = readExact(4) else { break }
    let len = Int(lenData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
    guard let payload = readExact(len) else { break }

    autoreleasepool {
        switch cmd {
        case 1: // ParseConfig
            do {
                let cfg = try VaultConfig.parse(payload)
                var out = sha256(cfg.serialized())
                out.append(contentsOf: cfg.inboxPublicKey)
                sendSuccess(out)
            } catch {
                sendError(error)
            }

        case 2: // DecodeMetadata
            do {
                let meta = try Metadata.parse(padded: payload)
                sendSuccess(metaSummary(meta))
            } catch {
                sendError(error)
            }

        case 3: // DecryptObject
            guard payload.count >= 16 else {
                sendError(NdesError.malformed("payload too short"))
                return
            }
            do {
                let expectedID = try fileIDFromBytes([UInt8](payload[0..<16]))
                let objData = payload[16...]
                let input = DataInput(objData)
                let out = DataOutput()
                let meta = try vault.decryptObject(input, expected: expectedID, to: out)
                var res = sha256(out.data)
                res.append(metaSummary(meta))
                sendSuccess(res)
            } catch {
                sendError(error)
            }

        case 4: // DecryptInbox
            guard payload.count >= 16 else {
                sendError(NdesError.malformed("payload too short"))
                return
            }
            do {
                let expectedID = try fileIDFromBytes([UInt8](payload[0..<16]))
                let inbData = payload[16...]
                let input = DataInput(inbData)
                let reader = try vault.openInbox(input, expected: expectedID)
                let out = DataOutput()
                try reader.decryptAll(to: out)
                var res = sha256(out.data)
                res.append(metaSummary(reader.metadata))
                sendSuccess(res)
            } catch {
                sendError(error)
            }

        case 5: // IngestInbox
            guard payload.count >= 16 else {
                sendError(NdesError.malformed("payload too short"))
                return
            }
            do {
                let expectedID = try fileIDFromBytes([UInt8](payload[0..<16]))
                let inbData = payload[16...]
                let input = DataInput(inbData)
                let out = DataOutput()
                let meta = try vault.ingest(inbox: input, expected: expectedID, to: out)
                let objInput = DataInput(out.data)
                let objOut = DataOutput()
                let meta2 = try vault.decryptObject(objInput, expected: expectedID, to: objOut)
                guard meta == meta2 else {
                    sendError(NdesError.metadata("ingested metadata mismatch"))
                    return
                }
                var res = sha256(objOut.data)
                res.append(metaSummary(meta))
                sendSuccess(res)
            } catch {
                sendError(error)
            }

        case 6: // DecodeRecoveryKey
            guard let str = String(data: payload, encoding: .utf8) else {
                sendError(NdesError.malformed("invalid utf8"))
                return
            }
            do {
                let v = try Vault(recoveryKey: str)
                sendSuccess(Data(v.exportVK()))
            } catch {
                sendError(error)
            }

        case 7: // ParseObjectPath
            guard let str = String(data: payload, encoding: .utf8) else {
                sendError(NdesError.path("invalid utf8"))
                return
            }
            do {
                let fid = try FileID(objectPath: str)
                let raw = hexDecode(fid.hex)
                sendSuccess(Data(raw))
            } catch {
                sendError(error)
            }

        case 8: // ParseInboxPath
            guard let str = String(data: payload, encoding: .utf8) else {
                sendError(NdesError.path("invalid utf8"))
                return
            }
            do {
                let fid = try FileID(inboxPath: str)
                let raw = hexDecode(fid.hex)
                sendSuccess(Data(raw))
            } catch {
                sendError(error)
            }

        case 9: // CompareIngested
            guard payload.count >= 20 else {
                sendError(NdesError.malformed("payload too short"))
                return
            }
            do {
                let expectedID = try fileIDFromBytes([UInt8](payload[0..<16]))
                let inbLen = Int(payload[16..<20].withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
                guard payload.count >= 20 + inbLen else {
                    sendError(NdesError.malformed("inbox length mismatch"))
                    return
                }
                let inbData = payload[20..<(20 + inbLen)]
                let objData = payload[(20 + inbLen)...]
                let result = try vault.compareIngested(
                    inbox: DataInput(inbData),
                    existingObject: DataInput(objData),
                    expected: expectedID
                )
                let code: UInt8 = (result == .alreadyIngested) ? 1 : 0
                sendSuccess(Data([code]))
            } catch {
                sendError(error)
            }

        default:
            sendError(NdesError.malformed("unknown cmd \(cmd)"))
        }
    }
}
