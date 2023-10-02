module SG::Nostr
  # OpenSSL examples: https://gist.github.com/ostinelli/1770a93d5c01376728c9
  
  class PrivateKey
    attr_reader :secret, :public_key
    
    def initialize secret, pub = nil
      @secret = secret
      @public_key = case pub
                    when PublicKey then pub
                    when nil then PublicKey.from_private(secret)
                    else PublicKey.new(pub)
                    end
    end

    # todo rename digest as it's not a digest, just similar output to Digest modules
        
    def hexdigest
      @secret.to_s(16).rjust(64, '0')
    end
    
    def digest
      ECDSA::Format::IntegerOctetString.encode(@secret, 32)
    end
    
    def to_bech32
      Bech32::Nostr::BareEntity.new('nsec', hexdigest).encode
    end
    
    def sign msg
      Schnorr.sign(msg, digest, SecureRandom.bytes(32)).encode
    end
    
    def verify msg, sig
      Schnorr.valid_sig?(msg, digest, sig)
    end
    
    def to_openssl
      group = OpenSSL::PKey::EC::Group.new('secp256k1')
      new_key = OpenSSL::PKey::EC.new(group)

      new_key.private_key = OpenSSL::BN.new(@secret, 16)
      new_key.public_key = OpenSSL::PK.new(group.generator.mul(new_key.private_key))
      new_key
    end

    def self.generate group = ECDSA::Group::Secp256k1, even_only: true
      priv = nil
      pub = nil
      begin
        #priv = 1 + SecureRandom.random_number(group.order - 1)
        priv = SecureRandom.random_number(group.order - 1)
        pub = PublicKey.from_private(priv, group)
      end until (even_only && pub.even?) || !even_only
      
      self.new(priv, pub)
    end
    
    def self.load str
      case str
      when /^nsec/ then new(Bech32::Nostr::NIP19.decode(str).data.to_i(16))
      when String then new(str.to_i(16))
      when Integer then new(str)
      else nil
      end
    end
  end
end
