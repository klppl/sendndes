import Foundation

/// Folder navigation over the flat listing: each file has a `dir` like "Photos/2026" ("" for the root).
/// Nothing here touches the vault; it only groups what `ndes ls` already returned.
public enum FolderTree {
    public struct Child: Identifiable, Hashable, Sendable {
        public let name: String
        public let path: String
        /// Files in this folder and everything below it.
        public let fileCount: Int
        public var id: String { path }
    }

    public struct Crumb: Identifiable, Hashable, Sendable {
        public let name: String
        public let path: String
        public var id: String { path }
    }

    /// True if `dir` is `folder` or lies below it.
    private static func isInside(_ dir: String, _ folder: String) -> Bool {
        folder.isEmpty || dir == folder || dir.hasPrefix(folder + "/")
    }

    /// The files stored directly in `folder`.
    public static func files(in folder: String, of entries: [FileEntry]) -> [FileEntry] {
        entries.filter { $0.dir == folder }
    }

    /// The subfolders one level below `folder`, in Finder-like order.
    public static func children(of folder: String, in entries: [FileEntry]) -> [Child] {
        var counts: [String: Int] = [:]
        for e in entries where !e.dir.isEmpty && e.dir != folder && isInside(e.dir, folder) {
            let rest = folder.isEmpty ? Substring(e.dir) : e.dir.dropFirst(folder.count + 1)
            let first = rest.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? String(rest)
            counts[first, default: 0] += 1
        }
        return counts
            .map { Child(name: $0.key, path: folder.isEmpty ? $0.key : folder + "/" + $0.key, fileCount: $0.value) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The path from the root down to `folder`, one crumb per component (the root itself is not included).
    public static func crumbs(_ folder: String) -> [Crumb] {
        var path = ""
        return folder.split(separator: "/", omittingEmptySubsequences: true).map {
            path = path.isEmpty ? String($0) : path + "/" + $0
            return Crumb(name: String($0), path: path)
        }
    }

    /// Whether `folder` still holds anything (the root always does).
    public static func exists(_ folder: String, in entries: [FileEntry]) -> Bool {
        folder.isEmpty || entries.contains { isInside($0.dir, folder) }
    }

    /// The parent of `folder` ("" for a top-level folder or the root).
    public static func parent(of folder: String) -> String {
        guard let i = folder.lastIndex(of: "/") else { return "" }
        return String(folder[..<i])
    }
}
