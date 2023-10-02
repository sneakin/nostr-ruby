require 'openssl'

module SG
  module Nostr
    module SSL
    end
  end
end

module SG::Nostr::SSL::Certificate
  class Authority
    attr_reader :root_key, :root_cert
    
    def initialize root_key, root_cert = nil
      @root_key = root_key
      @root_cert = root_cert || gen_root_cert
    end
    
    def gen_root_cert
      root_ca = OpenSSL::X509::Certificate.new
      root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
      root_ca.serial = rand(255)
      root_ca.subject = OpenSSL::X509::Name.parse "/DC=localhost/CN=Ruby CA"
      root_ca.issuer = root_ca.subject # root CA's are "self-signed"
      root_ca.public_key = @root_key.public_key
      root_ca.not_before = Time.now
      root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = root_ca
      ef.issuer_certificate = root_ca
      root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
      root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, keyEncipherment, keyAgreement, dataEncipherment, cRLSign, digitalSignature", true))
      root_ca.add_extension(ef.create_extension("extendedKeyUsage", "serverAuth"))
      root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
      root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
      root_ca.sign(@root_key, OpenSSL::Digest.new('SHA256'))  
      root_ca
    end
    
    def gen_cert pubkey
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = rand(255)
      cert.subject = OpenSSL::X509::Name.parse "/DC=localhost/CN=Ruby certificate"
      cert.issuer = @root_cert.subject # root CA is the issuer
      cert.public_key = pubkey
      cert.not_before = Time.now
      cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = @root_cert
      cert.add_extension(ef.create_extension("keyUsage","keyEncipherment, keyAgreement, dataEncipherment, digitalSignature", true))
      cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
      cert.sign(@root_key, OpenSSL::Digest.new('SHA256'))
      cert
    end
  end
end
