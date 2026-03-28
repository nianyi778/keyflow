class Keyflow < Formula
  desc "Developer key vault for storing, finding, and reusing API keys"
  homepage "https://github.com/nianyi778/keyflow"
  version "0.6.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-aarch64-apple-darwin.tar.gz"
      sha256 "ea43f343c8b294c005fbe1aaa8ac5c195f7b6894bbaaf13cf8f3ba880d05b5c1"
    end
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-apple-darwin.tar.gz"
      sha256 "ef3f46d0b1902bf00d1cbef39ae117c1d35caa6a26c8cdaa56f13802cbadf9e3"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1967cd46d90ecd6b1cc3a7ce296b67b6ff3384764a7f2f4c8f9adb09c521900a"
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
