const std = @import("std");

pub fn redact(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
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
