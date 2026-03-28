class Keyflow < Formula
  desc "Developer key vault for storing, finding, and reusing API keys"
  homepage "https://github.com/nianyi778/keyflow"
  version "0.6.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-aarch64-apple-darwin.tar.gz"
      sha256 "3c89a986c3447bd6d082dd5fff5e347674977ef0676eb9a4176737677471077c"
    end
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-apple-darwin.tar.gz"
      sha256 "2b3b044c2d297c7dafbd169abe3e188344409ea7061488b92a4bfeab8d7f297d"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "21fb5dbf07ad2713e516fe2c4ee887bc44a44d4e352f6a55b3f14eb4a5711f6e"
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
