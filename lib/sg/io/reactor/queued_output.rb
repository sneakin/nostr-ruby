require 'thread'

class SG::IO::Reactor
  class QueuedOutput < IOutput
    def initialize io, &cb
      super(io)
      @queue = Queue.new
      @cb = cb || lambda { |pkt| io.write_nonblock(pkt) }
      @closing = false
    end

    def close
      @closing = true
    end
    
    def flush
    end
    
    def << data
      @queue << data
      self
    end

    def write data
      @queue << data
      data.size
    end

    alias write_nonblock write
    
    def puts *lines
      lines.each { |l| write(l.to_s + "\n") }
    end
    
    def needs_processing?
      !closed? && (!@queue.empty? || @closing)
    end

    def process
      data = nil
      while !@queue.empty?
        data = @queue.pop
        @cb.call(data)
      end

      if @closing && !io.closed?
        io.close
        @closing = nil
      end
    rescue ::IO::EAGAINWaitWriteable, ::OpenSSL::SSL::SSLErrorWaitWriteable
      # todo partial data ever sent?
      @queue.unshift(data) if data
    end
  end
end
