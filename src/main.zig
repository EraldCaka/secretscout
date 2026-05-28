const std = @import("std");

const Allocator = std.mem.Allocator;
const max_file_size_bytes: u64 = 2 * 1024 * 1024;

pub const Rule = enum {
    aws_access_key,
    github_classic_token,
    github_token,
    slack_token,
    generic_secret,
    private_key_marker,

    pub fn label(self: Rule) []const u8 {
        return switch (self) {
            .aws_access_key => "aws-access-key",
            .github_classic_token => "github-classic-token",
            .github_token => "github-token",
            .slack_token => "slack-token",
            .generic_secret => "generic-secret",
            .private_key_marker => "private-key-marker",
        };
    }
};

pub const Finding = struct {
    file: []const u8,
    line: usize,
    column: usize,
    rule: Rule,
    preview: []const u8,
};

pub const Config = struct {
    target_path: []const u8,
    json_output: bool = false,
    fail_on_findings: bool = false,
};

const Match = struct {
    start: usize,
    len: usize,
};

const TokenFlavor = enum {
    github,
    slack,
};

const Scanner = struct {
    allocator: Allocator,
    config: Config,
    findings: std.ArrayList(Finding),

    pub fn init(allocator: Allocator, config: Config) Scanner {
        return .{
            .allocator = allocator,
            .config = config,
            .findings = std.ArrayList(Finding).init(allocator),
        };
    }

    pub fn deinit(self: *Scanner) void {
        for (self.findings.items) |finding| {
            self.allocator.free(finding.file);
            self.allocator.free(finding.preview);
        }
        self.findings.deinit();
    }

    pub fn scan(self: *Scanner) !void {
        try self.scanPath(self.config.target_path);
    }

    fn scanPath(self: *Scanner, path: []const u8) !void {
        if (std.fs.cwd().openIterableDir(path, .{ .access_sub_paths = true })) |dir| {
            dir.close();
            try self.scanDirectory(path);
            return;
        } else |err| switch (err) {
            error.NotDir => try self.scanFile(path),
            else => return err,
        }
    }

    fn scanDirectory(self: *Scanner, path: []const u8) !void {
        if (isIgnoredDirName(std.fs.path.basename(path))) return;

        var dir = try std.fs.cwd().openIterableDir(path, .{ .access_sub_paths = true });
        defer dir.close();

        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            switch (entry.kind) {
                .directory => {
                    if (isIgnoredDirName(entry.name)) continue;

                    const child_path = try std.fs.path.join(self.allocator, &[_][]const u8{ path, entry.name });
                    defer self.allocator.free(child_path);
                    try self.scanDirectory(child_path);
                },
                .file => {
                    const child_path = try std.fs.path.join(self.allocator, &[_][]const u8{ path, entry.name });
                    defer self.allocator.free(child_path);
                    try self.scanFile(child_path);
                },
                else => {},
            }
        }
    }

    fn scanFile(self: *Scanner, path: []const u8) !void {
        var file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const stat = try file.stat();
        if (stat.size > max_file_size_bytes) return;

        var sample_buf: [4096]u8 = undefined;
        const sample_len = try file.readAll(sample_buf[0..]);
        if (isLikelyBinary(sample_buf[0..sample_len])) return;
        try file.seekTo(0);

        const content = try file.readToEndAlloc(self.allocator, max_file_size_bytes);
        defer self.allocator.free(content);

        try self.scanContent(path, content);
    }

    fn scanContent(self: *Scanner, path: []const u8, content: []const u8) !void {
        var line_number: usize = 1;
        var line_start: usize = 0;
        var index: usize = 0;

        while (index <= content.len) : (index += 1) {
            if (index == content.len or content[index] == '\n') {
                const line_end = if (index > line_start and content[index - 1] == '\r') index - 1 else index;
                try self.scanLine(path, line_number, content[line_start..line_end]);
                line_number += 1;
                line_start = index + 1;
            }
        }
    }

    fn scanLine(self: *Scanner, path: []const u8, line_number: usize, line: []const u8) !void {
        try self.detectAwsKeys(path, line_number, line);
        try self.detectGitHubTokens(path, line_number, line);
        try self.detectSlackTokens(path, line_number, line);
        try self.detectGenericAssignments(path, line_number, line);
        try self.detectPrivateKeyMarkers(path, line_number, line);
    }

    fn detectAwsKeys(self: *Scanner, path: []const u8, line_number: usize, line: []const u8) !void {
        const prefixes = [_][]const u8{ "AKIA", "ASIA" };
        for (prefixes) |prefix| {
            var index: usize = 0;
            while (index + 20 <= line.len) : (index += 1) {
                if (!std.mem.eql(u8, line[index .. index + 4], prefix)) continue;
                if (!isTokenBoundaryBefore(line, index)) continue;
                if (!hasOnlyUppercaseAlnum(line[index + 4 .. index + 20])) continue;
                if (!isTokenBoundaryAfter(line, index + 20)) continue;

                try self.addFinding(path, line_number, .aws_access_key, .{
                    .start = index,
                    .len = 20,
                }, line[index .. index + 20]);
            }
        }
    }

    fn detectGitHubTokens(self: *Scanner, path: []const u8, line_number: usize, line: []const u8) !void {
        try self.detectPrefixedToken(path, line_number, line, "ghp_", .github_classic_token, 20, .github);
        try self.detectPrefixedToken(path, line_number, line, "github_pat_", .github_token, 20, .github);
        try self.detectPrefixedToken(path, line_number, line, "gho_", .github_token, 20, .github);
        try self.detectPrefixedToken(path, line_number, line, "ghu_", .github_token, 20, .github);
        try self.detectPrefixedToken(path, line_number, line, "ghs_", .github_token, 20, .github);
        try self.detectPrefixedToken(path, line_number, line, "ghr_", .github_token, 20, .github);
    }

    fn detectSlackTokens(self: *Scanner, path: []const u8, line_number: usize, line: []const u8) !void {
        try self.detectPrefixedToken(path, line_number, line, "xoxb-", .slack_token, 10, .slack);
        try self.detectPrefixedToken(path, line_number, line, "xoxp-", .slack_token, 10, .slack);
        try self.detectPrefixedToken(path, line_number, line, "xoxa-", .slack_token, 10, .slack);
    }

    fn detectPrefixedToken(
        self: *Scanner,
        path: []const u8,
        line_number: usize,
        line: []const u8,
        prefix: []const u8,
        rule: Rule,
        min_suffix_len: usize,
        token_flavor: TokenFlavor,
    ) !void {
        var index: usize = 0;
        while (index + prefix.len <= line.len) : (index += 1) {
            if (!std.mem.eql(u8, line[index .. index + prefix.len], prefix)) continue;
            if (!isTokenBoundaryBefore(line, index)) continue;

            var end = index + prefix.len;
            while (end < line.len and isTokenChar(line[end], token_flavor)) : (end += 1) {}
            if (end - (index + prefix.len) < min_suffix_len) continue;
            if (!isTokenBoundaryAfter(line, end)) continue;

            try self.addFinding(path, line_number, rule, .{
                .start = index,
                .len = end - index,
            }, line[index..end]);
        }
    }

    fn detectGenericAssignments(self: *Scanner, path: []const u8, line_number: usize, line: []const u8) !void {
        var index: usize = 0;
        while (index < line.len) : (index += 1) {
            var operator_len: usize = 0;
            if (line[index] == ':' and index + 1 < line.len and line[index + 1] == '=') {
                operator_len = 2;
            } else if (line[index] == '=' or line[index] == ':') {
                operator_len = 1;
            } else {
                continue;
            }

            const key = extractAssignmentKey(line[0..index]);
            if (key.len == 0 or !containsSecretKeyword(key)) continue;

            var value_start = index + operator_len;
            while (value_start < line.len and isHorizontalWhitespace(line[value_start])) : (value_start += 1) {}
            if (value_start >= line.len) continue;

            var quote: ?u8 = null;
            if (line[value_start] == '"' or line[value_start] == '\'') {
                quote = line[value_start];
                value_start += 1;
            }
            if (value_start >= line.len) continue;

            var value_end = value_start;
            while (value_end < line.len) : (value_end += 1) {
                const ch = line[value_end];
                if (quote) |q| {
                    if (ch == q) break;
                } else if (isUnquotedValueTerminator(ch)) {
                    break;
                }
            }

            const value = trimTrailingPunctuation(line[value_start..value_end]);
            if (value.len < 12) continue;
            if (!isSuspiciousValue(value)) continue;

            try self.addFinding(path, line_number, .generic_secret, .{
                .start = value_start,
                .len = value.len,
            }, value);
        }
    }

    fn detectPrivateKeyMarkers(self: *Scanner, path: []const u8, line_number: usize, line: []const u8) !void {
        const markers = [_][]const u8{
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        };

        for (markers) |marker| {
            var search_from: usize = 0;
            while (std.mem.indexOfPos(u8, line, search_from, marker)) |match_index| {
                try self.addFinding(path, line_number, .private_key_marker, .{
                    .start = match_index,
                    .len = marker.len,
                }, marker);
                search_from = match_index + marker.len;
            }
        }
    }

    fn addFinding(
        self: *Scanner,
        path: []const u8,
        line_number: usize,
        rule: Rule,
        match: Match,
        preview_source: []const u8,
    ) !void {
        const file_copy = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(file_copy);

        const preview = if (rule == .private_key_marker)
            try self.allocator.dupe(u8, preview_source)
        else
            try redact(self.allocator, preview_source);
        errdefer self.allocator.free(preview);

        try self.findings.append(.{
            .file = file_copy,
            .line = line_number,
            .column = match.start + 1,
            .rule = rule,
            .preview = preview,
        });
    }
};

pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const exit_code = run(gpa.allocator()) catch |err| {
        switch (err) {
            error.InvalidArguments => std.process.exit(2),
            else => {
                std.io.getStdErr().writer().print("runtime error: {}\n", .{err}) catch {};
                std.process.exit(2);
            },
        }
    };
    std.process.exit(exit_code);
}

fn run(allocator: Allocator) !u8 {
    const config = try parseArgs(allocator);
    defer allocator.free(config.target_path);

    var scanner = Scanner.init(allocator, config);
    defer scanner.deinit();

    try scanner.scan();

    if (config.json_output) {
        try writeJson(std.io.getStdOut().writer(), scanner.findings.items);
    } else {
        try writeHuman(std.io.getStdOut().writer(), scanner.findings.items);
    }

    if (config.fail_on_findings and scanner.findings.items.len > 0) {
        return 1;
    }
    return 0;
}

fn parseArgs(allocator: Allocator) !Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        try printUsage(std.io.getStdErr().writer());
        return error.InvalidArguments;
    }

    var path: ?[]const u8 = null;
    var json_output = false;
    var fail_on_findings = false;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            try printUsage(std.io.getStdOut().writer());
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--json")) {
            json_output = true;
        } else if (std.mem.eql(u8, arg, "--fail-on-findings")) {
            fail_on_findings = true;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            try std.io.getStdErr().writer().print("unknown flag: {s}\n", .{arg});
            try printUsage(std.io.getStdErr().writer());
            return error.InvalidArguments;
        } else if (path == null) {
            path = arg;
        } else {
            try std.io.getStdErr().writer().print("unexpected argument: {s}\n", .{arg});
            try printUsage(std.io.getStdErr().writer());
            return error.InvalidArguments;
        }
    }

    if (path == null) {
        try printUsage(std.io.getStdErr().writer());
        return error.InvalidArguments;
    }

    const target_path = try allocator.dupe(u8, path.?);
    return .{
        .target_path = target_path,
        .json_output = json_output,
        .fail_on_findings = fail_on_findings,
    };
}

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage:
        \\  secretscout <path>
        \\  secretscout <path> --json
        \\  secretscout <path> --fail-on-findings
        \\  secretscout --help
        \\
        \\Options:
        \\  --json               Print findings as JSON.
        \\  --fail-on-findings   Exit with code 1 if any findings are found.
        \\  --help               Show this help message.
        \\
    );
}

fn writeHuman(writer: anytype, findings: []const Finding) !void {
    for (findings) |finding| {
        try writer.print("{s}:{d}:{d} [{s}] {s}\n", .{
            finding.file,
            finding.line,
            finding.column,
            finding.rule.label(),
            finding.preview,
        });
    }
}

fn writeJson(writer: anytype, findings: []const Finding) !void {
    try writer.writeByte('[');
    for (findings, 0..) |finding, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeByte('\n');
        try writer.writeAll("  {\"file\":\"");
        try writeJsonEscaped(writer, finding.file);
        try writer.writeAll("\",\"line\":");
        try writer.print("{d}", .{finding.line});
        try writer.writeAll(",\"column\":");
        try writer.print("{d}", .{finding.column});
        try writer.writeAll(",\"rule\":\"");
        try writeJsonEscaped(writer, finding.rule.label());
        try writer.writeAll("\",\"preview\":\"");
        try writeJsonEscaped(writer, finding.preview);
        try writer.writeAll("\"}");
    }

    if (findings.len > 0) {
        try writer.writeByte('\n');
    }
    try writer.writeByte(']');
    try writer.writeByte('\n');
}

fn writeJsonEscaped(writer: anytype, input: []const u8) !void {
    for (input) |ch| {
        switch (ch) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (ch < 0x20) {
                    try writer.print("\\u00{x:0>2}", .{ch});
                } else {
                    try writer.writeByte(ch);
                }
            },
        }
    }
}

fn escapeJsonAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    errdefer buffer.deinit();
    try writeJsonEscaped(buffer.writer(), input);
    return buffer.toOwnedSlice();
}

fn redact(allocator: Allocator, value: []const u8) ![]u8 {
    if (value.len <= 6) {
        return allocator.dupe(u8, "***");
    }

    const prefix_len: usize = if (value.len >= 8) 4 else 2;
    const suffix_len: usize = if (value.len >= 8) 3 else 2;
    return std.fmt.allocPrint(allocator, "{s}...{s}", .{
        value[0..prefix_len],
        value[value.len - suffix_len ..],
    });
}

fn isLikelyBinary(sample: []const u8) bool {
    if (sample.len == 0) return false;

    var suspicious: usize = 0;
    for (sample) |ch| {
        if (ch == 0) return true;
        if (ch < 0x09) {
            suspicious += 1;
            continue;
        }
        if (ch > 0x0D and ch < 0x20) {
            suspicious += 1;
        }
    }

    return suspicious * 5 > sample.len;
}

fn isIgnoredDirName(name: []const u8) bool {
    return std.mem.eql(u8, name, ".git") or
        std.mem.eql(u8, name, "zig-cache") or
        std.mem.eql(u8, name, "zig-out") or
        std.mem.eql(u8, name, "node_modules") or
        std.mem.eql(u8, name, "target") or
        std.mem.eql(u8, name, ".venv");
}

fn isTokenBoundaryBefore(line: []const u8, index: usize) bool {
    if (index == 0) return true;
    return !isIdentifierChar(line[index - 1]) and line[index - 1] != '-';
}

fn isTokenBoundaryAfter(line: []const u8, index: usize) bool {
    if (index >= line.len) return true;
    return !isIdentifierChar(line[index]) and line[index] != '-';
}

fn hasOnlyUppercaseAlnum(slice: []const u8) bool {
    for (slice) |ch| {
        if (!((ch >= 'A' and ch <= 'Z') or isAsciiDigit(ch))) return false;
    }
    return true;
}

fn isIdentifierChar(ch: u8) bool {
    return isAsciiAlnum(ch) or ch == '_';
}

fn isTokenChar(ch: u8, flavor: TokenFlavor) bool {
    return switch (flavor) {
        .github => isIdentifierChar(ch) or ch == '_',
        .slack => isIdentifierChar(ch) or ch == '-',
    };
}

fn isHorizontalWhitespace(ch: u8) bool {
    return ch == ' ' or ch == '\t';
}

fn isUnquotedValueTerminator(ch: u8) bool {
    return isHorizontalWhitespace(ch) or ch == ',' or ch == ';' or ch == ')' or ch == ']' or ch == '}' or ch == '#';
}

fn extractAssignmentKey(prefix: []const u8) []const u8 {
    const trimmed = std.mem.trimRight(u8, prefix, " \t");
    var start = trimmed.len;
    while (start > 0) {
        const ch = trimmed[start - 1];
        if (isIdentifierChar(ch) or ch == '-' or ch == '.') {
            start -= 1;
        } else {
            break;
        }
    }
    return trimmed[start..];
}

fn containsSecretKeyword(key: []const u8) bool {
    const keywords = [_][]const u8{ "api_key", "apikey", "secret", "token", "password" };
    for (keywords) |keyword| {
        if (containsIgnoreCase(key, keyword)) return true;
    }
    return false;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        var matched = true;
        var inner: usize = 0;
        while (inner < needle.len) : (inner += 1) {
            if (asciiLower(haystack[index + inner]) != asciiLower(needle[inner])) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}

fn trimTrailingPunctuation(value: []const u8) []const u8 {
    var end = value.len;
    while (end > 0) {
        const ch = value[end - 1];
        if (ch == ',' or ch == ';') {
            end -= 1;
        } else {
            break;
        }
    }
    return value[0..end];
}

fn isSuspiciousValue(value: []const u8) bool {
    var alpha: usize = 0;
    var digit: usize = 0;
    var punctuation: usize = 0;

    for (value) |ch| {
        if (isAsciiAlphabetic(ch)) {
            alpha += 1;
        } else if (isAsciiDigit(ch)) {
            digit += 1;
        } else if (ch == '_' or ch == '-' or ch == '/' or ch == '+' or ch == '=' or ch == '.') {
            punctuation += 1;
        } else {
            return false;
        }
    }

    if (alpha == 0 and digit == 0) return false;
    if (digit == 0 and punctuation == 0 and alpha < 16) return false;
    return true;
}

fn isAsciiDigit(ch: u8) bool {
    return ch >= '0' and ch <= '9';
}

fn isAsciiAlphabetic(ch: u8) bool {
    return (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z');
}

fn isAsciiAlnum(ch: u8) bool {
    return isAsciiAlphabetic(ch) or isAsciiDigit(ch);
}

fn asciiLower(ch: u8) u8 {
    if (ch >= 'A' and ch <= 'Z') return ch + 32;
    return ch;
}

test "detects AWS access keys" {
    var scanner = Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLine("config.txt", 4, "aws_key = AKIA1234567890ABCDEF");

    try std.testing.expectEqual(@as(usize, 1), scanner.findings.items.len);
    try std.testing.expectEqual(Rule.aws_access_key, scanner.findings.items[0].rule);
    try std.testing.expectEqualStrings("AKIA...DEF", scanner.findings.items[0].preview);
}

test "detects GitHub tokens" {
    var scanner = Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLine("secrets.env", 2, "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456");

    try std.testing.expectEqual(@as(usize, 2), scanner.findings.items.len);
    try std.testing.expectEqual(Rule.github_classic_token, scanner.findings.items[0].rule);
    try std.testing.expectEqual(Rule.generic_secret, scanner.findings.items[1].rule);
}

test "detects generic secret assignments" {
    var scanner = Scanner.init(std.testing.allocator, .{ .target_path = "." });
    defer scanner.deinit();

    try scanner.scanLine("app.env", 1, "api_key := \"supersecret12345\"");

    try std.testing.expectEqual(@as(usize, 1), scanner.findings.items.len);
    try std.testing.expectEqual(Rule.generic_secret, scanner.findings.items[0].rule);
    try std.testing.expectEqualStrings("supe...345", scanner.findings.items[0].preview);
}

test "redaction preserves prefix and suffix" {
    const redacted = try redact(std.testing.allocator, "github_pat_abcdefghijklmnopqrstuvwxyz");
    defer std.testing.allocator.free(redacted);

    try std.testing.expectEqualStrings("gith...xyz", redacted);
}

test "JSON escaping handles control characters" {
    const escaped = try escapeJsonAlloc(std.testing.allocator, "\"line\"\n\t\\");
    defer std.testing.allocator.free(escaped);

    try std.testing.expectEqualStrings("\\\"line\\\"\\n\\t\\\\", escaped);
}
