class SG::IO::Reactor
  class BasicInput < IInput
    def initialize io, &cb
      super(io)
      @cb = cb
    end

    def process
      @cb.call
    end
  end
end
