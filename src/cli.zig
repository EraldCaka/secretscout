const std = @import("std");
const types = @import("types.zig");

pub fn parseArgs(allocator: std.mem.Allocator) !types.Config {
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

    return .{
        .target_path = try allocator.dupe(u8, path.?),
        .json_output = json_output,
        .fail_on_findings = fail_on_findings,
    };
}

pub fn printUsage(writer: anytype) !void {
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

pub fn exitCodeForFindings(fail_on_findings: bool, finding_count: usize) u8 {
    if (fail_on_findings and finding_count > 0) return 1;
    return 0;
}
