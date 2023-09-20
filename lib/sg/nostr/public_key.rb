module SG::Nostr
  class PublicKey
    attr_reader :key

    def self.from_private priv, group = ECDSA::Group::Secp256k1
      self.new(group.generator.multiply_by_scalar(priv))
    end
    
    def self.load str
      case str
      when /^npub/ then new(Bech32::Nostr::NIP19.decode(str).data)
      when String then new(str)
      when ECDSA::Point then new(str)
      else nil
      end
    end

    def initialize bytes
      @key = if String === bytes # todo rely on #load
               ECDSA::Format::PointOctetString.decode(SG::Hex.dehex(bytes), ECDSA::Group::Secp256k1)
             else
               bytes
             end
    end
    
    def even?
      @key.y.even?
    end
    
    def hexdigest
      SG::Hex.hex(digest)
    end
    
    def digest
      ECDSA::Format::PointOctetString.encode(@key, compression: true)[-32,32]
    end

    def to_bech32
      Bech32::Nostr::BareEntity.new('npub', hexdigest).encode
    end
    
    def make_ssl_key bytes
      group = OpenSSL::PKey::EC::Group.new('secp256k1')
      key = OpenSSL::PKey::EC.new(group)
      public_key_bn = OpenSSL::BN.new("02" + bytes, 16)
      public_key = OpenSSL::PKey::EC::Point.new(group, public_key_bn)
      key.public_key = public_key
      @key = key
    end
    
    def verify msg, sig
      Schnorr.valid_sig?(msg, digest, sig)
    end
  end
end
