require 'forwardable'

module SG::IO
  class Multiplexer
    attr_reader :input, :output
    
    def initialize i, o
      @input = i
      @output = o
    end

    extend Forwardable
    def_delegators :@input, :read, :read_nonblock, :gets, :readline, :each_line, :readbyte, :binread
    def_delegators :@output, :write, :write_nonblock, :puts, :writebyte, :binwrite

    def flush
      input.flush
      output.flush
      self
    end
    
    def close_read
      (OpenSSL::SSL::SSLSocket === input ? input.close : input.close_read)
    end
    
    def close_write
      (OpenSSL::SSL::SSLSocket === output ? output.close : output.close_write)
    end
        
    def close dir = nil
      # SSLSocket only has #close
      close_read unless dir == :output
      close_write unless dir == :input
      self
    end
    
    def closed?
      input.closed? && output.closed?
    end

    def eof?
      input.eof? # || output.eof?
    end
  end
end
