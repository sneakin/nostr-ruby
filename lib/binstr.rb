#!/usr/bin/env -S bundle exec ruby
# coding: utf-8

require 'sg/web_socket'
require 'sg/hex'
require 'sg/nostr'

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
        SG::Nostr::PublicKey.new(SG::Hex.hex(pubkey)).verify(canonicalize.pack, sig)
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

require 'thread'

class BinstrServer
  class Client
    def initialize io, up_queue
      @io = io
      @ws = SG::WebSocket.new(io)
      @framer = Binstr.new(@ws)
      @up_queue = up_queue
      @to_send = Queue.new
    end

    def process_input
      begin
        @framer.read_frames do |f|
          @ws.pong(f) if f.opcode == :ping
          next unless Binstr::Frame === f
          if f.payload.valid?
            @up_queue << f
          else
            @framer.send_msg('error', "Invalid signature")
          end
        end
      rescue EOFError, Errno::ECONNRESET
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
      !@to_send.empty?
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
    @listeners = [ io ]
    @clients = {}
    @queue = Queue.new
  end

  def process timeout = nil
    i,o,e = IO.select(@listeners + @clients.keys,
                      @clients.collect { |cio, c| cio if c.has_output? }.reject(&:nil?),
                      [], timeout)
    i.each do |ci|
      if cl= @clients[ci]
        cl.process_input
      elsif listener= @listeners.find(ci).first
        sock = listener.accept
        @clients[sock] = Client.new(sock, @queue)
      end
    end if i

    o.each do |co|
      cl = @clients[co]
      cl.process_output if cl
    end if o

    @clients.delete_if { |_, c| c.closed? }

    while !@queue.empty?
      f = @queue.pop
      @clients.each do |cio, c|
        c.send_frame(f)
      end
    end

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
