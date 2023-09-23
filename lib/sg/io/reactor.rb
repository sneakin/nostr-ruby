require 'thread'
require 'sg/constants'

module SG
  module IO
  end
end

class SG::IO::Reactor
  class Source
    attr_reader :io

    def initialize io
      @io = io
    end
    
    def closed?
      io.closed?
    end
    
    def needs_processing?
      false
    end
    
    def process
    end
  end

  class IInput < Source
    def needs_processing?; true; end
  end

  class IOutput < Source
  end
  
  class BasicInput < IInput
    def initialize io, &cb
      super(io)
      @cb = cb
    end

    def process
      @cb.call
    end
  end
  
  class Listener < IInput
    def initialize sock, dispatcher, &cb
      super(sock)
      @dispatcher = dispatcher
      @cb = cb || raise(ArgumentError.new('No accept callback block given.'))
    end

    def process
      sock = io.accept
      cin, cout = @cb.call(sock)
      @dispatcher.add_input(cin, sock) if cin
      @dispatcher.add_output(cout, sock) if cout
    end
  end
  
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

  class QueuedOutput < IOutput
    def initialize io, &cb
      super(io)
      @queue = Queue.new
      @cb = cb || lambda { |pkt| io.write_nonblock(pkt) }
    end

    def << data
      @queue << data
      self
    end
    
    def needs_processing?
      !@queue.empty?
    end

    def process
      data = nil
      while needs_processing?
        data = @queue.pop
        @cb.call(data)
      end
    rescue ::IO::EAGAINWaitWriteable, ::OpenSSL::SSL::SSLErrorWaitWriteable
      # todo partial data ever sent?
      @queue.unshift(data) if data
    end
  end
  
  class DispatchSet
    attr_reader :ios
    
    def initialize
      @ios = {}
    end

    def add actor, io = actor.io
      @ios[io] = actor
    end

    def delete actor
      io = IO === actor ? actor : actor.io
      @ios.delete(io)
    end

    def process ios
      ios.each do |io|
        cl = @ios[io]
        cl.process if cl
      end if ios

      cleanup_closed
    end

    def cleanup_closed
      @ios.delete_if { |io, _| io.closed? }
      self
    end

    def needs_processing
      @ios.select { |_, actor| actor.needs_processing? }
    end
  end

  #
  # The reactor's methods:
  #
  
  def initialize
    @inputs = DispatchSet.new
    @outputs = DispatchSet.new
    @errs = DispatchSet.new
    @idlers = []
    @done = false
  end

  def add_input actor_or_io, io = nil, &cb
    add_io(@inputs, actor_or_io, io, BasicInput, &cb)
  end

  def add_io set, actor_or_io, io, actor_kind, &cb
    if actor_or_io && cb
      set.add(actor_kind.new(actor_or_io, &cb), actor_or_io)
    elsif actor_or_io
      set.add(actor, io || actor.io)
    else
      raise ArgumentError.new("Expected an IO and block, or Actor and IO.")
    end
  end

  def del_input actor
    @inputs.delete(actor)
  end

  def add_listener io, &cb
    add_input(Listener.new(io, self, &cb))
  end
  
  def add_output actor, io = actor.io
    add_io(@outputs, actor, io, BasicOutput, &cb)
  end

  def del_output actor
    @outputs.delete(actor)
  end

  def add_err actor, io = actor.io
    add_io(@errs, actor, io, BasicOutput, &cb)
  end

  def del_err actor
    @errs.delete(actor)
  end

  def add_idler &cb
    @idlers << cb
  end

  def del_idler fn
    @idlers.delete(fn)
  end

  def process timeout: nil
    i,o,e = ::IO.select(@inputs.needs_processing.keys,
                        @outputs.needs_processing.keys,
                        @errs.needs_processing.keys,
                        timeout)
    # todo timers?
    if i || o
      @inputs.process(i)
      @outputs.process(o)
      @errs.process(e)
    else
      @idlers.each { |i| i.call }
    end
      
    self
  end

  def done!
    @done = true
  end

  def done?
    @done
  end
  
  def serve! timeout: nil, &cb
    if cb
      until done?
        process(timeout: timeout)
        cb.call
      end
    else
      process(timeout: timeout) until done?
    end
  end
end

