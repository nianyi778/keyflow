class Keyflow < Formula
  desc "Developer key vault for storing, finding, and reusing API keys"
  homepage "https://github.com/nianyi778/keyflow"
  version "0.7.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-aarch64-apple-darwin.tar.gz"
      sha256 "1a6d3ca3b2260d31a79a5bbb703cf3195d4e8c3912cd773c535e0b61109c8995"
    end
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-apple-darwin.tar.gz"
      sha256 "4684bdd3e1778433a99c110790003ef44ef3ecc5f0b69df492cf8efe96cf660b"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "48b8f4945112d6f0db41b0c1c03acc8df18e100638bc43315c9cd7c077d514ea"
    end
  end

  def install
    bin.install "keyflow"
    bin.install "kf"
  end

  test do
    assert_match "keyflow", shell_output("#{bin}/kf --version")
  end
end
