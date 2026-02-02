# Template: update `url` and `sha256` for each release.
# Two install strategies are supported:
#   1. Source build (below) — requires Rust toolchain
#   2. Bottle/binary — use `url` pointing to prebuilt release archive + sha256
class Tirith < Formula
  desc "URL security analysis for shell environments"
  homepage "https://github.com/sheeki03/tirith"
  # TODO: uncomment and fill for each release
  # url "https://github.com/sheeki03/tirith/archive/refs/tags/v#{version}.tar.gz"
  # sha256 "PLACEHOLDER"
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/tirith")

    # Generate completions via hidden subcommands
    output = Utils.safe_popen_read(bin/"tirith", "completions", "bash")
    (bash_completion/"tirith").write output
    output = Utils.safe_popen_read(bin/"tirith", "completions", "zsh")
    (zsh_completion/"_tirith").write output
    output = Utils.safe_popen_read(bin/"tirith", "completions", "fish")
    (fish_completion/"tirith.fish").write output

    # Generate man page
    output = Utils.safe_popen_read(bin/"tirith", "manpage")
    (man1/"tirith.1").write output

    # Install shell hooks (init search path: ../share/tirith/shell)
    (share/"tirith/shell").install "shell/tirith.sh"
    (share/"tirith/shell/lib").install Dir["shell/lib/*"]
  end

  def caveats
    <<~EOS
      Add to your shell profile:
        eval "$(tirith init)"
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tirith --version")
    # Doctor should exit 0
    system bin/"tirith", "doctor"
  end
end
