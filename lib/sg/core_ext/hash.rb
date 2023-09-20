class Hash
  def symbolize_keys
    self.class[self.collect { |k, v| [ k.to_sym, v ] }]
  end
  def stringify_keys
    self.class[self.collect { |k, v| [ k.to_s, v ] }]
  end
end
