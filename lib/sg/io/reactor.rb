require 'sg/constants'

module SG
  module IO
  end
end

require 'sg/io/multiplexer'
require 'sg/io/reactor/source'
require 'sg/io/reactor/basic_input'
require 'sg/io/reactor/basic_output'
require 'sg/io/reactor/queued_output'
require 'sg/io/reactor/listener'
require 'sg/io/reactor/dispatch_set'

class SG::IO::Reactor
  def initialize
    @inputs = DispatchSet.new
    @outputs = DispatchSet.new
    @errs = DispatchSet.new
    @idlers = []
    @done = false
  end

  def << actor
    case actor
    when IInput then add_input(actor)
    when IOutput then add_output(actor)
    else raise ArgumentError.new("Only IInput and IOutput allowed")
    end
  end
  
  def delete actor
    del_input(actor)
    del_output(actor)
    del_err(actor)
    self
  end
  
  def add_to_set set, actor_or_io, io, actor_kind, &cb
    if actor_or_io && cb
      set.add(actor_kind.new(actor_or_io, &cb), actor_or_io)
    elsif actor_or_io
      set.add(actor_or_io, io || actor_or_io.io)
    else
      raise ArgumentError.new("Expected an IO and block, or Actor and IO.")
    end
  end

  def add_input actor_or_io, io = nil, &cb
    $stderr.puts("Adding input: #{actor_or_io.inspect} #{io.inspect}")
    add_to_set(@inputs, actor_or_io, io, BasicInput, &cb)
  end

  def del_input actor
    @inputs.delete(actor)
  end

  def add_listener io, &cb
    add_input(Listener.new(io, self, &cb))
  end
  
  def add_output actor, io = nil, &cb
    add_to_set(@outputs, actor, io, BasicOutput, &cb)
  end

  def del_output actor
    @outputs.delete(actor)
  end

  def add_err actor, io = nil, &cb
    add_to_set(@errs, actor, io, BasicOutput, &cb)
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
    ios = [ @inputs.needs_processing.keys,
            @outputs.needs_processing.keys,
            @errs.needs_processing.keys
          ]
    $stderr.puts("Reactor select #{ios.inspect}") 
    i,o,e = ::IO.select(*ios, timeout) unless ios.all?(&:empty?)
    if i || o || e
      @inputs.process(i)
      @outputs.process(o)
      @errs.process(e)
    end
    
    @idlers.each { |i| i.call }
      
    self
  end

  def flush
    i,o,e = ::IO.select([],
                        @outputs.needs_processing.keys,
                        @errs.needs_processing.keys,
                        0)
    @outputs.process(o) if o
    @errs.process(e) if e
    self
  end

  def done!
    flush
    @done = true
  end

  def done?
    @done
  end
  
  def serve! timeout: 60, &cb
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

