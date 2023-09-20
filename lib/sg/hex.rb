module SG
  module Hex
    def self.dehex str
      [ str ].pack('H*')
    end
    
    def self.hex str
      str.unpack('H*').first
    end
  end
end
