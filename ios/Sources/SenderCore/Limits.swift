import Foundation

/// Limits the phone app enforces. One definition; the UI text and the server defaults derive from it.
public enum SenderLimits {
    /// 90 MiB of plaintext per file. The Mac app takes larger files.
    public static let maxFileBytes: Int64 = 94_371_840
    public static let maxItemsPerShare = 20
    /// Failed items stay this long, then they are discarded.
    public static let failedItemLifetime: TimeInterval = 7 * 24 * 3600
    public static let defaultFolder = "iPhone"
    public static let maxNameBytes = 200
    public static let maxPayloadCharacters = 2048

    public static var maxFileDescription: String { "90 MiB" }
    public static let tooLargeMessage = "Maximum 90 MiB per file. Use the Mac app for larger files."
}
