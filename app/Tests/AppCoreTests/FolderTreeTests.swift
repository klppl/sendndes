import XCTest
@testable import AppCore

final class FolderTreeTests: XCTestCase {
    private func entry(_ id: String, _ name: String, _ dir: String) -> FileEntry {
        FileEntry(id: id, size: 1, mtime: Date(timeIntervalSince1970: 0), name: name, dir: dir)
    }

    private lazy var entries = [
        entry("1", "top.txt", ""),
        entry("2", "a.jpg", "Photos"),
        entry("3", "b.jpg", "Photos/2026"),
        entry("4", "c.jpg", "Photos/2026"),
        entry("5", "d.jpg", "Photos/2025/Trip"),
        entry("6", "x.pdf", "Docs"),
        entry("7", "y.pdf", "Photosynthesis"),   // shares a prefix with "Photos" but is another folder
    ]

    func testRootShowsTopLevelFoldersAndFiles() {
        XCTAssertEqual(FolderTree.files(in: "", of: entries).map(\.name), ["top.txt"])
        let kids = FolderTree.children(of: "", in: entries)
        XCTAssertEqual(kids.map(\.name), ["Docs", "Photos", "Photosynthesis"])
        XCTAssertEqual(kids.map(\.fileCount), [1, 4, 1])
    }

    func testNestedFolder() {
        XCTAssertEqual(FolderTree.files(in: "Photos", of: entries).map(\.name), ["a.jpg"])
        let kids = FolderTree.children(of: "Photos", in: entries)
        XCTAssertEqual(kids.map(\.path), ["Photos/2025", "Photos/2026"])
        XCTAssertEqual(kids.map(\.fileCount), [1, 2])
        XCTAssertEqual(FolderTree.children(of: "Photos/2025", in: entries).map(\.path), ["Photos/2025/Trip"])
        XCTAssertTrue(FolderTree.children(of: "Photos/2026", in: entries).isEmpty)
    }

    func testPrefixSiblingIsNotInside() {
        XCTAssertFalse(FolderTree.children(of: "Photos", in: entries).contains { $0.name == "synthesis" })
        XCTAssertFalse(FolderTree.exists("Phot", in: entries))
        XCTAssertTrue(FolderTree.exists("Photos/2025", in: entries))
        XCTAssertTrue(FolderTree.exists("", in: []))
    }

    func testCrumbsAndParent() {
        XCTAssertEqual(FolderTree.crumbs("").count, 0)
        XCTAssertEqual(FolderTree.crumbs("Photos/2026").map(\.path), ["Photos", "Photos/2026"])
        XCTAssertEqual(FolderTree.parent(of: "Photos/2026"), "Photos")
        XCTAssertEqual(FolderTree.parent(of: "Photos"), "")
        XCTAssertEqual(FolderTree.parent(of: ""), "")
    }
}
