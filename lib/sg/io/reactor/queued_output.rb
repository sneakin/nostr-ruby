require 'thread'

class SG::IO::Reactor
  class QueuedOutput < IOutput
    def initialize io, &cb
      super(io)
      @queue = []
      @cb = cb || lambda { |pkt| io.write_nonblock(pkt) }
      @closing = false
    end

    def close
      @closing = true
    end

    alias close_write close
    
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
      if lines.empty?
        write("\n")
      else
        lines.each { |l| write(l.to_s + "\n") }
      end
    end
    
    def needs_processing?
      !closed? && (!@queue.empty? || @closing)
    end

    def process
      amt = 0
      data = nil
      while !@queue.empty?
        data = @queue.shift
        amt = @cb.call(data)
        @queue.unshift(data[amt..-1]) if amt < data.size
      end

      if @closing && !io.closed?
        io.close
        @closing = nil
      end
    rescue ::IO::WaitWritable, ::OpenSSL::SSL::SSLErrorWaitWritable
      @queue.unshift(data[amt..-1]) if data && amt < data.size
    rescue Errno::EPIPE
      # fixme necessary? more cases?
      io.close
      @closing = nil
    end
  end
end
