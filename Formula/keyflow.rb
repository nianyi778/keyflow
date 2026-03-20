class Keyflow < Formula
  desc "Developer key vault for storing, finding, and reusing API keys"
  homepage "https://github.com/nianyi778/keyflow"
  version "0.6.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-aarch64-apple-darwin.tar.gz"
      sha256 "f51a1f5c2edf9babc07324c9905e16ed79a193f95573aca6687e30216b2c6a6a"
    end
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-apple-darwin.tar.gz"
      sha256 "6b3015bfab5e4f5a598a2684009f0fcb17ccc92ed8b2ebe281652cda863726d8"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "71e1323c29e40f96cada542f75956d9e2d4335f3817a9e345dd07e8c1ba5eba1"
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
