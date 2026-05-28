const std = @import("std");
const cli = @import("cli.zig");
const output = @import("output.zig");
const preview = @import("preview.zig");
const scanner_mod = @import("scanner.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");

test "detects AWS access keys" {
    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLineForTest("config.txt", 4, "aws_key = AKIA1234567890ABCDEF");

    try std.testing.expectEqual(@as(usize, 1), scanner.findings.items.len);
    try std.testing.expectEqual(types.Rule.aws_access_key, scanner.findings.items[0].rule);
    try std.testing.expectEqualStrings("AKIA...DEF", scanner.findings.items[0].preview);
}

test "detects GitHub tokens" {
    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLineForTest("secrets.env", 2, "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456");

    try std.testing.expectEqual(@as(usize, 2), scanner.findings.items.len);
    try std.testing.expectEqual(types.Rule.github_classic_token, scanner.findings.items[0].rule);
    try std.testing.expectEqual(types.Rule.generic_secret, scanner.findings.items[1].rule);
}

test "detects generic secret assignments" {
    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLineForTest("app.env", 1, "api_key := \"supersecret12345\"");

    try std.testing.expectEqual(@as(usize, 1), scanner.findings.items.len);
    try std.testing.expectEqual(types.Rule.generic_secret, scanner.findings.items[0].rule);
    try std.testing.expectEqualStrings("supe...345", scanner.findings.items[0].preview);
}

test "redaction preserves prefix and suffix" {
    const redacted = try preview.redact(std.testing.allocator, "github_pat_abcdefghijklmnopqrstuvwxyz");
    defer std.testing.allocator.free(redacted);

    try std.testing.expectEqualStrings("gith...xyz", redacted);
}

test "JSON escaping handles control characters" {
    const escaped = try output.escapeJsonAlloc(std.testing.allocator, "\"line\"\n\t\\");
    defer std.testing.allocator.free(escaped);

    try std.testing.expectEqualStrings("\\\"line\\\"\\n\\t\\\\", escaped);
}

test "scans directories recursively and ignores junk directories" {
    var workspace = try test_support.TestWorkspace.init(std.testing.allocator);
    defer workspace.deinit();

    try workspace.writeFile("src/app.env", "api_key = supersecret12345\n");
    try workspace.writeFile("node_modules/ignored.env", "api_key = ignoredsecret12345\n");

    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = workspace.root_path });
    defer scanner.deinit();

    try scanner.scan();

    try std.testing.expectEqual(@as(usize, 1), scanner.findings.items.len);
    try std.testing.expectEqual(types.Rule.generic_secret, scanner.findings.items[0].rule);
    try std.testing.expect(std.mem.indexOf(u8, scanner.findings.items[0].file, "src/app.env") != null);
}

test "skips binary-looking files" {
    var workspace = try test_support.TestWorkspace.init(std.testing.allocator);
    defer workspace.deinit();

    try workspace.writeBytes("bin/blob.dat", &[_]u8{ 0x00, 0x01, 0x02, 'A', 'K', 'I', 'A', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F' });

    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = workspace.root_path });
    defer scanner.deinit();

    try scanner.scan();

    try std.testing.expectEqual(@as(usize, 0), scanner.findings.items.len);
}

test "skips oversized files before scanning contents" {
    var workspace = try test_support.TestWorkspace.init(std.testing.allocator);
    defer workspace.deinit();

    try workspace.writeLargeFile(
        "logs/huge.env",
        "api_key = supersecret12345\n",
        scanner_mod.max_file_size_bytes + 1,
    );

    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = workspace.root_path });
    defer scanner.deinit();

    try scanner.scan();

    try std.testing.expectEqual(@as(usize, 0), scanner.findings.items.len);
}

test "human-readable output formats findings" {
    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLineForTest("src/config.env", 3, "api_key=supersecret12345");

    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try output.writeHuman(buffer.writer(), scanner.findings.items);

    try std.testing.expectEqualStrings(
        "src/config.env:3:9 [generic-secret] supe...345\n",
        buffer.items,
    );
}

test "JSON output formats findings as escaped objects" {
    var scanner = scanner_mod.Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLineForTest("dir/quoted\"file.env", 7, "token = \"abc123def456ghi789\"");

    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try output.writeJson(buffer.writer(), scanner.findings.items);

    try std.testing.expectEqualStrings(
        "[\n  {\"file\":\"dir/quoted\\\"file.env\",\"line\":7,\"column\":10,\"rule\":\"generic-secret\",\"preview\":\"abc1...789\"}\n]\n",
        buffer.items,
    );
}

test "fail-on-findings exit code is deterministic" {
    try std.testing.expectEqual(@as(u8, 0), cli.exitCodeForFindings(false, 0));
    try std.testing.expectEqual(@as(u8, 0), cli.exitCodeForFindings(false, 3));
    try std.testing.expectEqual(@as(u8, 0), cli.exitCodeForFindings(true, 0));
    try std.testing.expectEqual(@as(u8, 1), cli.exitCodeForFindings(true, 1));
}
