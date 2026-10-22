import Foundation

/// One sealed file waiting for (or past) its upload. The sealed bytes live next to it as `<id>.inb`, and are
/// never re-sealed: a retry sends the same bytes under the same id, which the server treats as idempotent.
public struct SealedItem: Codable, Equatable, Sendable, Identifiable {
    public enum State: String, Codable, Sendable { case sealed, uploading, stored, failed }

    public enum FailureReason: String, Codable, Sendable {
        case tokenRejected, conflict, serverFull, tooLargeForServer, rejectedByServer, fileMissing, unexpected, pairedElsewhere

        public var message: String {
            switch self {
            case .tokenRejected: return "The server rejected the token. Scan the QR code again."
            case .conflict: return "The server already has a different file under this id. Discard it and share the file again."
            case .serverFull: return "The server is out of space."
            case .tooLargeForServer: return "The server (or the network in front of it) refused a file this large."
            case .rejectedByServer: return "The server did not accept the file."
            case .fileMissing: return "The encrypted file is gone from this phone."
            case .unexpected: return "The server's answer was not what send n*des expects (a login page or a redirect in front of it?). The file is kept; try again."
            case .pairedElsewhere: return "This file was locked for a different server or vault than the one this phone is paired with now. Discard it and share it again."
            }
        }
    }

    /// The file_id as 32 lowercase hex characters; also the server path and the file name on disk.
    public let id: String
    /// Shown in the list on this phone only. The server never sees it (it is sealed inside the file).
    public let displayName: String
    public let size: Int64
    public let sealedSize: Int64
    public var state: State
    public var failure: FailureReason?
    public var attempts: Int
    public let createdAt: Date
    public var updatedAt: Date
    /// The check value of the pairing it was locked for: a file is only ever sent to the server it was locked for.
    public var pairingFP: String?
    /// Which background session owns the running upload ("app" or "share").
    public var session: String?
    /// After a 429 or a 5xx the item waits until this time.
    public var notBefore: Date?

    public var isFinished: Bool { state == .stored }
}

public struct HistoryEntry: Codable, Equatable, Sendable, Identifiable {
    public enum Status: String, Codable, Sendable { case stored, failed, discarded, expired }
    public let id: String
    public let name: String
    public let size: Int64
    public let status: Status
    public let date: Date

    /// Honest wording: the server has the sealed file; nobody has opened it yet.
    public var statusText: String {
        switch status {
        case .stored: return "Stored on server"
        case .failed: return "Not sent"
        case .discarded: return "Discarded"
        case .expired: return "Gave up after 7 days"
        }
    }
}
