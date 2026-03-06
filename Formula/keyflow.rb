class Keyflow < Formula
  desc "AI-Native Secret Manager — Let AI coding assistants discover and use your API keys"
  homepage "https://github.com/nianyi778/keyflow"
  version "0.3.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-aarch64-apple-darwin.tar.gz"
      sha256 "3b7e2b27599e1f12354b000eeaea0056b81d9f89b19827b0afec1482dd6b6637"
    end
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-apple-darwin.tar.gz"
      sha256 "da457222dfddaee41df18be2164995dac0ca18af33fba190f73c8fdeade2095d"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nianyi778/keyflow/releases/download/v#{version}/keyflow-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "34d1bc637877186a13e3fc472e3a92221112ca360081f2bcbbd9374d34a486f8"
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
