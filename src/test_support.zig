const std = @import("std");

pub const TestWorkspace = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,

    pub fn init(allocator: std.mem.Allocator) !TestWorkspace {
        const root_path = try std.fmt.allocPrint(allocator, ".secretscout-test-{d}", .{std.time.nanoTimestamp()});
        errdefer allocator.free(root_path);
        try std.fs.cwd().makePath(root_path);
        return .{
            .allocator = allocator,
            .root_path = root_path,
        };
    }

    pub fn deinit(self: *TestWorkspace) void {
        std.fs.cwd().deleteTree(self.root_path) catch {};
        self.allocator.free(self.root_path);
    }

    pub fn writeFile(self: *TestWorkspace, relative_path: []const u8, data: []const u8) !void {
        const full_path = try self.join(relative_path);
        defer self.allocator.free(full_path);

        if (std.fs.path.dirname(full_path)) |dir_name| {
            try std.fs.cwd().makePath(dir_name);
        }

        var file = try std.fs.cwd().createFile(full_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(data);
    }

    pub fn writeBytes(self: *TestWorkspace, relative_path: []const u8, data: []const u8) !void {
        try self.writeFile(relative_path, data);
    }

    pub fn writeLargeFile(self: *TestWorkspace, relative_path: []const u8, prefix: []const u8, total_size: u64) !void {
        const full_path = try self.join(relative_path);
        defer self.allocator.free(full_path);

        if (std.fs.path.dirname(full_path)) |dir_name| {
            try std.fs.cwd().makePath(dir_name);
        }

        var file = try std.fs.cwd().createFile(full_path, .{ .truncate = true });
        defer file.close();

        try file.writeAll(prefix);
        try file.setEndPos(total_size);
    }

    pub fn join(self: *TestWorkspace, relative_path: []const u8) ![]u8 {
        return std.fs.path.join(self.allocator, &[_][]const u8{ self.root_path, relative_path });
    }
};
