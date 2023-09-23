require 'sg/io/reactor'

class SG::IO::Reactor::LineReader < SG::IO::Reactor::IInput
  def initialize io, sep = "\n", read_size: nil, &cb
    super(io)
    @separator = sep
    @buffer = ''
    @read_size = read_size || 4096
    @cb = cb
  end

  def needs_processing?
    !@eof && super
  end
  
  def do_read
    while data = @io.read_nonblock(@read_size)
      @buffer += data
    end
  rescue IO::EAGAINWaitReadable
  rescue EOFError
    @eof = true
  end

  def do_cb
    if @cb
      while line= next_line
        @cb.call(line)
      end

      @cb.call(:eof) if @eof
    end
  end
  
  def process
    do_read
    do_cb
  end

  def next_line
    idx = @buffer.index(@separator)
    if idx
      line, rest = @buffer.split_at(idx + 1)
      @buffer = rest
      return line
    else
      return nil
    end
  end
end
