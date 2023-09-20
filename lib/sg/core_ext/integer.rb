class Integer
  def nth_byte byte
    (self >> (byte * 8)) & 0xFF
  end
    
  # todo unused
  def self.revbits bits = 32
    bits.times.reduce(0) do |a, i|
      a | (((self >> i) & 1) << (bits-1-i))
    end
  end
end
