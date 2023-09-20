module SG::Nostr
  class Message
    attr_accessor :id, :pubkey, :created_at, :kind, :tags, :content, :sig
    attr_reader :req
    
    def initialize req: nil, id: nil, pubkey: nil, created_at: nil, kind: nil, tags: nil, content: nil, sig: nil
      @req = req
      @id = id
      @pubkey = String === pubkey ? PublicKey.new(pubkey) : pubkey
      @created_at = created_at
      @kind = kind
      @tags = tags || []
      @content = content
      @sig = sig
    end

    def to_h
      { id: id,
        pubkey: pubkey.hexdigest,
        created_at: created_at.to_i,
        kind: kind,
        tags: tags,
        content: content,
        sig: sig
      }
    end
    
    def to_json
      JSON.dump(to_h)
    end
    
    def canonical_form
      [ 0, pubkey.hexdigest[-64, 64], (created_at || 0).to_i, (kind || 0).to_i, tags, content.to_s ]
    end
    
    def canonical_json
      JSON.dump(canonical_form)
    end
    
    def hexdigest
      Digest::SHA256.hexdigest(canonical_json)
    end
    
    def digest
      Digest::SHA256.digest(canonical_json)
    end
    
    def sign! key
      @pubkey = key.public_key
      @id = hexdigest
      s = key.sign(SG::Hex.dehex(@id))
      @sig = SG::Hex.hex(s.encode)
      self
    end
    
    def verify
      @pubkey.verify(SG::Hex.dehex(id || hexdigest), SG::Hex.dehex(@sig))
    end
  end
end
