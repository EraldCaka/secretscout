const std = @import("std");
const cli = @import("cli.zig");
const output = @import("output.zig");
const scanner_mod = @import("scanner.zig");

pub fn run(allocator: std.mem.Allocator) !u8 {
    const config = try cli.parseArgs(allocator);
    defer allocator.free(config.target_path);

    var scanner = scanner_mod.Scanner.init(allocator, config);
    defer scanner.deinit();

    try scanner.scan();

    if (config.json_output) {
        try output.writeJson(std.io.getStdOut().writer(), scanner.findings.items);
    } else {
        try output.writeHuman(std.io.getStdOut().writer(), scanner.findings.items);
    }

    return cli.exitCodeForFindings(config.fail_on_findings, scanner.findings.items.len);
}
