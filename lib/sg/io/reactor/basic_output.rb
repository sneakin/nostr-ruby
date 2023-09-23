class SG::IO::Reactor
  class BasicOutput < IOutput
    def initialize io, needs_processing: nil, &cb
      super(io)
      @cb = cb
      @needs_processing = needs_processing
    end

    def needs_processing?
      @needs_processing.call if @needs_processing
    end

    def process
      @cb.call
    end
  end
end
