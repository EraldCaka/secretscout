const std = @import("std");
const app = @import("app.zig");

pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const exit_code = app.run(gpa.allocator()) catch |err| {
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
