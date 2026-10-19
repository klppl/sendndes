import Foundation

public struct UploadSpec: Equatable {
    public let url: URL
    public let name: String
    public let dir: String
}

public struct ExpandedInput {
    public var specs: [UploadSpec] = []
    public var skipped: [String] = []   // sanitized names, for display
    public var tooMany = false
}

/// Turns dropped/chosen file URLs into uploads. Regular files only; symlinks, devices, FIFOs and
/// sockets are skipped and listed. Folders are walked physically (no symlink following).
public enum InputExpander {
    public static let maxFiles = 1000
    static let maxDepth = 32

    public static func expand(_ urls: [URL]) -> ExpandedInput {
        var out = ExpandedInput()
        for u in urls where u.isFileURL {
            var st = stat()
            guard lstat(u.path, &st) == 0 else { out.skipped.append(DisplayName.sanitize(u.lastPathComponent)); continue }
            switch st.st_mode & S_IFMT {
            case S_IFREG:
                add(UploadSpec(url: u, name: u.lastPathComponent, dir: ""), to: &out)
            case S_IFDIR:
                walk(u.path, rel: u.lastPathComponent, depth: 0, into: &out)
            default:
                out.skipped.append(DisplayName.sanitize(u.lastPathComponent))
            }
            if out.tooMany { break }
        }
        return out
    }

    private static func add(_ s: UploadSpec, to out: inout ExpandedInput) {
        if out.specs.count >= maxFiles { out.tooMany = true; return }
        out.specs.append(s)
    }

    private static func walk(_ path: String, rel: String, depth: Int, into out: inout ExpandedInput) {
        guard depth < maxDepth, let d = opendir(path) else { return }
        defer { closedir(d) }
        var names: [String] = []
        while let e = readdir(d) {
            let n = withUnsafePointer(to: &e.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) { String(cString: $0) } }
            if n == "." || n == ".." || n == ".DS_Store" || n.hasPrefix("._") { continue }
            names.append(n)
        }
        for n in names.sorted() {
            if out.tooMany { return }
            let p = path + "/" + n
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }
            switch st.st_mode & S_IFMT {
            case S_IFREG: add(UploadSpec(url: URL(fileURLWithPath: p), name: n, dir: rel), to: &out)
            case S_IFDIR: walk(p, rel: rel + "/" + n, depth: depth + 1, into: &out)
            default: out.skipped.append(DisplayName.sanitize(n))
            }
        }
    }
}
