/// A 16-byte file_id. Public code gets one only from a path (the expected id
/// for a reader, SPEC 4.1) or from a writer that generated it randomly.
public struct FileID: Hashable, Sendable, CustomStringConvertible {
    let bytes: [UInt8]

    init(bytes: [UInt8]) {
        precondition(bytes.count == 16)
        self.bytes = bytes
    }

    /// 32 lowercase hex characters.
    public var hex: String { hexEncode(bytes) }
    public var description: String { hex }

    /// `objects/<first 2 hex>/<32 hex>.obj`, relative to the vault.
    public var objectPath: String { "objects/\(hex.prefix(2))/\(hex).obj" }
    /// `inbox/<32 hex>.inb`, relative to the vault.
    public var inboxPath: String { "inbox/\(hex).inb" }

    /// The expected file_id of an object at `path` (any path ending in
    /// `<dir>/<name>`). The name must be exactly `<32 lowercase hex>.obj`
    /// and `<dir>` must equal its first two hex characters.
    public init(objectPath path: String) throws {
        let parts = Array(path.utf8).split(separator: 0x2F, omittingEmptySubsequences: false)
        guard parts.count >= 2 else { throw ValvError.path("object path needs a prefix directory") }
        let id = try FileID.parseName(parts[parts.count - 1], ext: ".obj")
        let dir = [UInt8](parts[parts.count - 2])
        guard dir == Array(id.hex.utf8.prefix(2)) else {
            throw ValvError.path("object is not in the directory named by its first two hex characters")
        }
        self = id
    }

    /// The expected file_id of an inbox file at `path`; its name must be
    /// exactly `<32 lowercase hex>.inb`.
    public init(inboxPath path: String) throws {
        let parts = Array(path.utf8).split(separator: 0x2F, omittingEmptySubsequences: false)
        self = try FileID.parseName(parts[parts.count - 1], ext: ".inb")
    }

    private static func parseName(_ name: ArraySlice<UInt8>, ext: String) throws -> FileID {
        let e = Array(ext.utf8)
        guard name.count == 32 + e.count, name.suffix(e.count).elementsEqual(e),
              let raw = hexDecodeLowercase(name.prefix(32)) else {
            throw ValvError.path("name must be exactly 32 lowercase hex characters plus \(ext)")
        }
        return FileID(bytes: raw)
    }
}
