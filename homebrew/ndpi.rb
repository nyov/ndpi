require "formula"

class Ndpi < Formula
  homepage "http://www.ntop.org/products/ndpi/"
  url 'https://svn.ntop.org/svn/ntop/trunk/nDPI/'
  version "1.2"
  head 'https://svn.ntop.org/svn/ntop/trunk/nDPI/'

  depends_on :autoconf => :build
  depends_on :automake => :build
  depends_on 'pkg-config' => :build
  depends_on :libtool => :build

  def install
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end

  test do
    `#{bin}/ndpiReader -i en1 -s 5`
    assert_equal 0, $?.exitstatus
  end

end
