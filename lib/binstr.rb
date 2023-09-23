#!/usr/bin/env -S bundle exec ruby
# coding: utf-8

require 'sg/web_socket'
require 'sg/hex'
require 'sg/nostr'
require 'forwardable'
require 'sg/io/reactor'
require 'sg/io/reactor/line_reader'

class Binstr
  ProtocolId = 0x1234
  
  class Frame
    class Bin < Struct.new(:id, :type, :pubkey, :sig, :data)
      # Protocol ID, Type, pubkey, sig, data
      Packing = 'S<S<a32a64a*'
      
      def pack
        to_a.pack(Packing)
      end

      def self.unpack str
        new(*str.unpack(Packing))        
      end

      def to_a
        self.class.members.collect { |m| self[m] }
      end

      def canonicalize
        dup.tap { |i| i.sig = Digest::SHA256.digest(data) }
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

  attr_reader :websocket
  
  def initialize ws
    @websocket = ws
  end

  def io
    @websocket.io
  end
  
  def close
    @websocket.close
  end
  
  def send_frame fr
    websocket.send_binary(fr.pack)
  end

  def send_msg key, txt
    send_frame(Frame::Bin.new(ProtocolId, 1, '', '', txt).sign(key))
  end

  def read_frames &cb
    return to_enum(__method__) unless cb
    
    websocket.read_frames do |frame|
      if frame.opcode == :text || frame.opcode == :binary
        if frame.payload[0,2].unpack('S<').first == ProtocolId
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

class BinstrServer
  class Client
    class HTTPState
      class ProtocolUpgraded < RuntimeError
      end
      
      def initialize io
        @io = io
      end
      
      def process_input
        # Read the HTTP request
        # Queue and send an HTTP response
      end
      
      def process_output pkt
      end
    end

    class WSState
      def initialize io, up_queue
        @io = io
        @ws = SG::WebSocket.new(@io)
        @framer = Binstr.new(@ws)
        @up_queue = up_queue
      end
      
      def process_input
        @framer.read_frames do |f|
          @ws.pong(f) if f.opcode == :ping
          next unless Binstr::Frame === f
          if f.payload.valid?
            @up_queue << f
          else
            send_frame(Frame::Bin.new(ProtocolId, 2, '', '', "Invalid signature."))
          end
        end
      rescue EOFError, Errno::ECONNRESET
        @ws.close
      end

      def send_frame fr
        @framer.send_frame(fr)
      end
    end
    
    def initialize io, up_queue
      @io = io
      @multi_io = SG::IO::Multiplexer.new(@io, output)
      @state = WSState.new(@multi_io, up_queue)
    end

    def closed?
      @io.closed?
    end

    def send_frame fr
      @state.send_frame(fr)
    end

    def input
      @input ||= SG::IO::Reactor::BasicInput.new(@io) do
        @state.process_input
      end
    end

    def output
      @output ||= SG::IO::Reactor::QueuedOutput.new(@io)
    end
  end

  def initialize
    @reactor = SG::IO::Reactor.new
    @clients = {}
    @queue = Queue.new
  end

  def add_listener io
    @reactor.add_listener(io) do |io|
      c = add_client(io)
      [ c.input, c.output ]
    end
  end

  def add_client io
    @clients[io] = Client.new(io, @queue)
  end
  
  def process timeout: nil
    @reactor.process(timeout: timeout)
    @clients.delete_if { |_, c| c.closed? }
    flush_queue
    self
  end

  def flush_queue
    while !@queue.empty?
      f = @queue.pop
      @clients.each do |cio, c|
        c.send_frame(f)
      end
    end
  end

  extend Forwardable
  def_delegators :@reactor, :done?, :done!
  
  def serve!
    process until done?
  end
end

if $0 == __FILE__
  case cmd= ARGV.shift
  when 'server' then
    port = (ARGV.shift || 4899).to_i
    puts("Listening on port #{port}.")
    sock = TCPServer.new(port)
    sock.listen(4)
    bs = BinstrServer.new
    bs.add_listener(sock)
    bs.serve!
  when 'send' then
    uri = URI.parse(ARGV.shift)
    msg = ARGV.shift || "Hello. The time is #{Time.now}."
    key = ENV['KEY']
    key = SG::Nostr::PrivateKey.load(key) || SG::Nostr::PrivateKey.generate
    client = Binstr.new(SG::WebSocket.new(TCPSocket.new(uri.host, uri.port)))
    client.send_msg(key, msg)
  when 'stream' then
    uri = URI.parse(ARGV.shift)
    key = ENV['KEY']
    key = SG::Nostr::PrivateKey.load(key) || SG::Nostr::PrivateKey.generate

    reactor = SG::IO::Reactor.new
    sock = TCPSocket.new(uri.host, uri.port)
    # reactor client output
    qo = SG::IO::Reactor::QueuedOutput.new(sock)
    mio = SG::IO::Multiplexer.new(sock, qo)
    ws = SG::WebSocket.new(mio)
    client = Binstr.new(ws)

    reactor.add_input(sock) do
      client.read_frames.each do |fr|
        if Binstr::Frame === fr
          payload = fr.payload
          puts("Bin: %s %s" % [ payload.valid?, payload.data ])
        else
          puts("???: %s" % [ fr.inspect ])
        end
      end
    end

    reactor.add_output(qo)

    lines = []
    reader = SG::IO::Reactor::LineReader.new($stdin) do |line|
      case line
      when :eof then
        puts("EOF")
        reactor.del_input(reader)
      when /\A\/ping/ then ws.ping
      when /\A\/quit/ then
        client.close
        reactor.done!
      else
        puts("\e[34m#{line.inspect}\e[0m")
        if line =~ /\A\s+\z/
          client.send_msg(key, lines.join("\n"))
          lines = []
        else
          lines << line
        end
      end
    end
    reactor.add_input(reader)
    
    reactor.serve!
  else raise "Unknown command"
  end
end
