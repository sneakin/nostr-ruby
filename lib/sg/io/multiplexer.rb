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
    
    def close dir = nil
      input.close unless dir == :output
      output.close unless dir == :input
      self
    end
    
    def closed?
      input.closed? && output.closed?
    end

    def eof?
      input.eof? && output.eof?
    end
  end
end
