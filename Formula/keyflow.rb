class Keyflow < Formula
  desc "Developer key vault for storing, finding, and reusing API keys"
  homepage "https://github.com/nianyi778/keyflow"
  version "0.9.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-aarch64-apple-darwin.tar.gz"
      sha256 "7c6864d615d8aef45ea840cb04eaf7a99b1a2e373daefab45b3f4682ecd9f5b3"
    end
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-apple-darwin.tar.gz"
      sha256 "07ff2122d0885f0e709f7253d9639f8740005643a62e2c89b53c6b255cd170c8"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "66d8ee8ca9312488a59e9fb90bfbdcf2c354f0d94688e1b67de92a109ceff785"
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
