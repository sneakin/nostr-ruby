#!/usr/bin/env -S bundle exec ruby
# coding: utf-8

require_relative 'nostr'

class Binstr
  attr_reader :websocket
  
  def initialize ws
    @websocket = ws
  end

  class Frame
    class Bin < Struct.new(:id, :type, :pubkey, :sig, :data)
      # Protocol ID, Type, pubkey, sig, data
      def pack
        to_a.pack('S<S<a32a64a*')
      end

      def self.unpack str
        new(*str.unpack('S<S<a32a64a*'))        
      end

      def to_a
        self.class.members.collect { |m| self[m] }
      end

      def canonicalize
        dup.tap { |i| i.sig = "\x00" * 0 }
      end
      
      def valid?
        NostrSocket::PublicKey.new(Hex.hex(pubkey)).verify(canonicalize.pack, sig)
      end

      def sign key
        canon = canonicalize
        self.pubkey = canon.pubkey = key.public_key.digest
        self.sig = key.sign(canon.pack)
        self
      end
    end
    
    attr_reader :frame
    
    def initialize frame
      @frame = frame
    end
    
    def unpack
      Bin.unpack(frame.payload)
    end

    def pack
      payload.pack
    end
    
    def method_missing mid, *a, **o, &cb
      @frame.send(mid, *a, **o, &cb)
    end
    
    def event_type
      js[1]
    end
    
    def payload
      @payload ||= unpack
    end    
  end

  def send_frame fr
    websocket.send_binary(fr.pack)
  end

  def send_msg key, txt
    send_frame(Frame::Bin.new(0x1234, 1, '', '', txt).sign(key))
  end

  def read_frames &cb
    return to_enum(__method__) unless cb
    
    websocket.read_frames do |frame|
      if frame.opcode == :text || frame.opcode == :binary
        if frame.payload[0,2] == "4\x12"
          cb.call(Frame.new(frame))
        else
          raise "Invalid payload #{frame.inspect}"
        end
      else
        cb.call(frame)
      end
    end
  end
end

class BinstrForkServer
  def initialize srv, workers: 4
    @serv_io = srv
    @max_workers = workers
    @workers = []
    @id = nil
  end

  def accept_connection
    io = @serv_io.accept
    ws = WebSocket.new(io)
    puts("#{@id}: Accepted #{io.inspect}")
    framer = Binstr.new(ws)
    begin
      framer.read_frames do |f|
        puts(f.payload.inspect)
        ws.pong(f) if f.opcode == :ping
        next unless Binstr::Frame === f
        puts(@id, f.payload.valid?, '')
        if f.payload.valid?
          framer.send_frame(f)
        end
      end
    rescue EOFError
    end until io.closed?
  end

  def spawn_worker id = 0
    @workers << Process.fork do
      @id = id
      accept_connection
    end
  end

  def cleanup
    @workers.each { |p| Process.kill('QUIT', p) }
    while @workers != []
      pid = Process.wait
      @workers.delete(pid) if pid
    end
  end
  
  def serve
    @max_workers.times do |n|
      spawn_worker(n)
    end
    trap('INT') { cleanup; exit(0) }
    trap('QUIT') { cleanup; exit(0) }
    at_exit { cleanup }
    while pid = Process.wait
      if @workers.include?(pid)
        status = $?
        puts("Exit #{pid} #{status}")
        @workers.delete(pid)
        spawn_worker(Time.now.to_i) if status.exitstatus != 0
      end
    end
  end
end

require 'thread'

class BinstrServer
  class Client
    def initialize io, out_queue
      @io = io
      @ws = WebSocket.new(io)
      @framer = Binstr.new(@ws)
      @out_queue = out_queue
      @to_send = Queue.new
    end

    def process_input
      begin
        @framer.read_frames do |f|
          @ws.pong(f) if f.opcode == :ping
          next unless Binstr::Frame === f
          if f.payload.valid?
            @out_queue << f
          else
            @framer.send_msg('error', "Invalid signature")
          end
        end
      rescue EOFError, Errno::Error
        @ws.close
      end
    end

    def closed?
      @io.closed?
    end

    def send_frame fr
      @to_send << fr
    end

    def has_output?
      @to_send.empty?
    end

    def process_output
      fr = nil
      while !@to_send.empty?
        fr = @to_send.pop
        @framer.send_frame(fr)
      end
    rescue IO::EAGAINWaitWriteable, OpenSSL::SSL::SSLErrorWaitWriteable
      @to_send.unshift(fr)
    end
  end
  
  def initialize io
    @io = io
    @clients = {}
    @queue = Queue.new
  end

  def process timeout = nil
    i,o,e = IO.select([@io, *@clients.keys],
                      @clients.collect { |cio, c| cio if c.has_output? },
                      [], timeout)
    i.each do |ci|
      if ci == @io
        sock = @io.accept
        @clients[sock] = Client.new(sock, @queue)
      end
      cl = @clients[ci]
      if cl
        cl.process_input
      end
    end if i

    while !@queue.empty?
      f = @queue.pop
      @clients.each do |cio, c|
        c.send_frame(f)
      end
    end

    o.each do |co|
      cl = @clients[co]
      cl.process_output if cl
    end if o

    @clients.delete_if { |_, c| c.closed? }
  end

  def serve
    while !@done
      process
    end
  end
end

if $0 == __FILE__
  sock = TCPServer.new(4899)
  sock.listen 4
  bs = BinstrServer.new(sock)
  bs.serve
end
