module Akami
  module AlgorithmHelper


    def digester
      @digester ||= OpenSSL::Digest.const_get(@digest_algorithm.to_s.upcase).new
    end

    def digest_algorithm_uri
      {
        sha1: "http://www.w3.org/2000/09/xmldsig#sha1",
        sha224: "http://www.w3.org/2001/04/xmldsig-more#sha224",
        sha256: "http://www.w3.org/2001/04/xmlenc#sha256",
        sha384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
        sha512: "http://www.w3.org/2001/04/xmlenc#sha512"
      }[@digest_algorithm]
    end
  end
end