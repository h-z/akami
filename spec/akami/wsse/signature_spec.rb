require 'spec_helper'

describe Akami::WSSE::Signature do

  let(:validator) { Akami::WSSE::VerifySignature.new(xml) }
  let(:xml) { '' }

  let(:fixtures_path) {
    File.join(Bundler.root, 'spec', 'fixtures', 'akami', 'wsse', 'signature' )
  }
  let(:cert_path) { File.join(fixtures_path, 'cert.pem') }
  let(:password) { 'password' }
  let(:digest_algorithm) { nil }

  let(:signature) {
    Akami::WSSE::Signature.new(
      Akami::WSSE::Certs.new(
        cert_file:            cert_path,
        private_key_file:     cert_path,
        private_key_password: password
      ),
      digest_algorithm: digest_algorithm
    )
  }

  context 'to_token' do
    let(:xml) { fixture('akami/wsse/signature/unsigned.xml') }

    it 'should ignore excessive whitespace' do
      signature.document = xml
      expect(signature.document).not_to include("  ")
    end

    {
      sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
      sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
      sha512: 'http://www.w3.org/2001/04/xmlenc#sha512',
      sha384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
      sha224: 'http://www.w3.org/2001/04/xmldsig-more#sha224'
    }.each do |algo, url|
      context "when digest algorithm is #{algo}" do
        let(:digest_algorithm) { algo }
        it "should digest with correct algorithm" do
          signature.document = xml
          digest = signature.to_token['ds:Signature']['ds:SignedInfo']['ds:Reference'].first
          body =  Nokogiri::XML(xml).xpath('//env:Body').first.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
          expect(digest['ds:DigestValue']).to eq(Base64.encode64(OpenSSL::Digest.const_get(algo.to_s.upcase).digest(body)).strip)
          expect(digest[:attributes!]['ds:DigestMethod/']['Algorithm']).to eq(url)
        end
      end
    end


    it 'should deep_merge with binary_security_token' do
      signature.document = xml
      expect(signature.to_token[:attributes!]['wsse:BinarySecurityToken']['xmlns:wsu']).
        to equal(Akami::WSSE::WSU_NAMESPACE)
      expect(signature.to_token[:attributes!]['ds:Signature']['xmlns:ds']).
        to equal(Akami::WSSE::Signature::SignatureNamespace)
    end
  end

end
