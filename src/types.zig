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
