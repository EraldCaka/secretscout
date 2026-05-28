const std = @import("std");
const types = @import("types.zig");

pub fn writeHuman(writer: anytype, findings: []const types.Finding) !void {
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

pub fn writeJson(writer: anytype, findings: []const types.Finding) !void {
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

pub fn escapeJsonAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    errdefer buffer.deinit();
    try writeJsonEscaped(buffer.writer(), input);
    return buffer.toOwnedSlice();
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
