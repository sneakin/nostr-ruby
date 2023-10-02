class Proc
  def partial_before *args
    self.class.new do |*a, **o, &b|
      self.call(*args, *a, **o, &b)
    end
  end

  def partial_after *args
    self.class.new do |*a, **o, &b|
      self.call(*a, *args, **o, &b)
    end
  end
  
  def partial_options **opts
    self.class.new do |*a, **o, &b|
      self.call(*a, **o.merge(opts), &b)
    end
  end
  
  def partial_defaults **opts
    self.class.new do |*a, **o, &b|
      self.call(*a, **opts.merge(o), &b)
    end
  end
  
  def compose other
    self.class.new do |*a, **o, &b|
      other.call(self.call(*a, **o, &b))
    end
  end

  def and &cb
    compose(cb)
  end
  
  def but *exes, &cb
    self.class.new do |*a, **o, &b|
      begin
        self.call(*a, **o, &b)
      rescue
        if exes.empty? || exes.include?($!.class)
          cb.call($!)
        else
          raise
        end
      end
    end
  end
  
end