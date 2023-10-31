#!/usr/bin/env -S bundle exec ruby
# coding: utf-8

require 'sg/web_socket'
require 'sg/hex'
require 'sg/nostr'
require 'forwardable'
require 'sg/io/reactor'
require 'sg/io/reactor/line_reader'
require 'sg/io/reactor/socket_connector'

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
      
      def public_key
        @public_key ||= SG::Nostr::PublicKey.new(SG::Hex.hex(pubkey))
      end
      
      def valid?
        public_key.verify(canonicalize.pack, sig)
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

# todo Nostr server

class BinstrServer
  class Client
    class HTTPState
      class BadRequest < RuntimeError
      end
      
      Request = Struct.new(:action, :path, :version, :headers)
      
      def initialize io, host: nil
        @io = io
        @reader = SG::IO::Reactor::LineReader.new(io)
        @req_lines = []
        @upgradable = false
        @erred = false
        @host = host
      end
      
      def upgradable?
        @upgradable
      end

      def drain
        @reader.drain
      end
            
      def send_frame fr
      end
      
      def process_input
        # todo need to close the socket after sending an error. QueuedOutput is processed after a direct call to #close. close in halves?
        # todo validation and errors sent before the blank line
        if @erred
          @io.close
          return
        end
        
        #raise EOFError if @reader.eof?
        @reader.process
        # Read the HTTP request
        req = read_request
        
        # Queue and send an HTTP response
        if req
          unless validate_request(req)
            @io.close_read
            @erred = true
            return
          end
          host = req.headers['Host']
          wskey = req.headers['Sec-WebSocket-Key']
          resp_key = Base64.encode64(Digest::SHA1.digest(wskey + SG::WebSocket::SEC_ACCEPT_SUFFIX)).gsub(/\s+/, '')          
          send_response(101, 'Okay', {
            'Host' => @host || host,
            'Connection' => 'Upgrade',
            'Upgrade' => 'websocket',
            'Sec-WebSocket-Accept' => resp_key
          })          
          
          @upgradable = true
        end
      rescue BadRequest
        # send HTTP error
        send_response(500, "Bad request", 'Host' => @host || 'nohost')
        @io.close_read
        @erred = true
      end

      RequiredHeaders = {
        'Host' => [ nil, 500, 'Bad host supplied' ],
        'Connection' => [ 'Upgrade', 426, 'Connection: Upgrade required' ],
        'Upgrade' => [ 'websocket', 426, 'Upgrade to wobsocket required' ],
        'Sec-WebSocket-Version' => [ '13', 500, 'Unsupported WebSocket version' ],
        'Sec-WebSocket-Key' => [ nil, 500, 'Sec-WebSocket-Key required' ],
      }
      
      def validate_request req
        return false if req.version != '1.1' || req.action != 'GET'
        
        RequiredHeaders.each do |header, (value, err, reason)|
          v = req.headers[header]
          if (value && v != value) || (value == nil && !v)
            send_response(err, reason, 'Host' => @host)
            return false
          end
        end
          
        return true
      end
            
      def send_response code, msg, headers
        resp = [ "HTTP/1.1 %s %s" % [ code, msg ] ]
        headers.each do |name, value|
          resp << "%s: %s" % [ name, value ]
        end
        resp << '' << ''
        @io.write(resp.join("\r\n"))
      end
      
      # todo object to parse in parts
      
      def read_request
        while true
          line = @reader.next_line
          $stderr.puts("read #{@io} #{line.inspect}")
          case line
          when nil then return false
          when :eof then
            @io.close
            return false
          when "\n" then break
          else
            @req_lines << line
          end
        end

        parse_request(@req_lines)
      end
      
      def parse_request lines
        if lines[0] =~ /^(\w+)\s+(\S+)\s+HTTP\/(\S+)$/
          action = $1
          path = $2
          version = $3
          headers = {}
          lines[1..-1].each do |line|
            if line =~ /^(\S+):\s+(.*)$/
	      if headers.has_key?($1)
	        headers[$1] = [ headers[$1] ] unless Array === headers[$1]
	        headers[$1] << $1
	      else
	        headers[$1] = $2
	      end
            else
              raise BadRequest.new(lines.join("\n"))
            end
          end

          return Request.new(action, path, version, headers)
        else
          raise BadRequest.new(lines.join("\n"))
        end
      end
    end

    class WSState
      def initialize io, up_queue, remaining_data
        @io = io
        @ws = SG::WebSocket.new(@io, init_data: remaining_data)
        @framer = Binstr.new(@ws)
        @up_queue = up_queue
      end

      def upgradable?; false; end
            
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
      @up_queue = up_queue
      @state = HTTPState.new(@multi_io)
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
        if @state.upgradable?
          data = @state.drain
          $stderr.puts("Upgrading #{@io.object_id} to WS: #{data.inspect}")
          @state = WSState.new(@multi_io, @up_queue, data)
        end
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
      $stderr.puts("Accepting #{io}")
      c = add_client(io)
      [ c.input, c.output ]
    end.on_error do |ex|
      $stderr.puts("Error:", ex, *ex.backtrace)
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
  require 'shellwords'
  #require 'webrick/https'
  require 'sg/nostr/ssl'
  require 'sg/selfhelp'
  
  case cmd= ARGV.shift
  when 'server' then # Starts a server.
    port = (ARGV.shift || 4899).to_i
    $stderr.puts("Listening on port #{port}.")
    sock = TCPServer.new(port)
    if ENV['SSL'].to_i > 0
      #key = ENV['KEY']
      #key = SG::Nostr::PrivateKey.load(key) || SG::Nostr::PrivateKey.generate
      #ca = SG::Nostr::SSL::Certificate::Authority.new(key.to_openssl)
      key = OpenSSL::PKey::RSA.new(1024)
      ca = SG::Nostr::SSL::Certificate::Authority.new(key)
      #cert, rsa = WEBrick::Utils.create_self_signed_cert(ENV['SSL'].to_i, [["CN", "localhost"]], "")
      sslctx = OpenSSL::SSL::SSLContext.new
      #sslctx.ssl_version = :TLSv12
      #sslctx.ecdh_curves = 'P-256' #'secp256k1'
      #sslctx.ciphers = sslctx.ciphers.select { |c| c[0] =~ /\AEC/ }
      sslctx.add_certificate(ca.root_cert, ca.root_key)
      #sslctx.extra_chain_cert = [ ca.root_cert ]
      #sslctx.ca_file = ca.root_cert.to_pem
      #sslctx.add_certificate(cert, rsa)
      sock = OpenSSL::SSL::SSLServer.new(sock, sslctx)
      sock.start_immediately = true
    end
    sock.listen(4)
    bs = BinstrServer.new
    bs.add_listener(sock)
    bs.serve!
  when 'send' then # Sends the second argument as a message to the server named by the first argument.
    uri = URI.parse(ARGV.shift)
    msg = ARGV.shift || "Hello. The time is #{Time.now}."
    key = ENV['KEY']
    key = SG::Nostr::PrivateKey.load(key) || SG::Nostr::PrivateKey.generate
    sock = TCPSocket.new(uri.host, uri.port)
    if uri.scheme == 'wss' || ENV['SSL'].to_i > 0
      sslctx = OpenSSL::SSL::SSLContext.new
      #sslctx.ciphers = sslctx.ciphers.select { |c| c[0] =~ /\AEC/ }
      #sslctx.ecdh_curves = 'secp256k1'
      sock = OpenSSL::SSL::SSLSocket.new(sock) #, sslctx)      
      sock.sync_close = true
      sock.connect
    end
    ws = SG::WebSocket.new(sock)
    ws.greet(uri.path, host: uri.host)
    client = Binstr.new(ws)
    client.send_msg(key, msg)
    client.close
  when 'stream' then # Connects to a server and prints any received message.
    uri = URI.parse(ARGV.shift)
    key = ENV['KEY']
    key = SG::Nostr::PrivateKey.load(key) || SG::Nostr::PrivateKey.generate

    client = nil
    reactor = SG::IO::Reactor.new
    reactor << SG::IO::Reactor::SocketConnector.tcp(uri.host, uri.port) do |sock|
      $stderr.puts("Connected #{sock}")
      # reactor client output
      if uri.scheme == 'wss' || ENV['SSL'].to_i > 0
        sslctx = OpenSSL::SSL::SSLContext.new
        #sslctx.ciphers = sslctx.ciphers.select { |c| c[0] =~ /\AEC/ }
        #sslctx.ecdh_curves = 'secp256k1'
        sock = OpenSSL::SSL::SSLSocket.new(sock) #, sslctx)      
        sock.sync_close = true
        sock.connect
      end
      qo = SG::IO::Reactor::QueuedOutput.new(sock)
      mio = SG::IO::Multiplexer.new(sock, qo)
      ws = SG::WebSocket.new(sock) # todo mio needs the reactor running, and connect can block
      ws.greet(uri.path, host: uri.host)
      ws.io = mio
      client = Binstr.new(ws)

      reactor.add_output(qo)

      reactor.add_input(mio.input) do
        client.read_frames.each do |fr|
          if Binstr::Frame === fr
            payload = fr.payload
            puts("\e[32mBin:\e[0m %s %s\n\e[1m%s\e[0m" % [ payload.valid?, payload.public_key.to_bech32, payload.data ])
          else
            puts("\e[32m???:\e[0m %s" % [ fr.inspect ])
          end
        end
      end
    end

    # todo not friendly to shell pipes
    
    cmds = {
      ping: lambda { ws.ping },
      quit: lambda {
        client.close if client
        reactor.done!
      },
      args: lambda { |*a| puts("Args: #{a.inspect}") }
    }
    lines = []
    reader = SG::IO::Reactor::LineReader.new($stdin) do |line|
      case line
      when :eof then
        $stderr.puts("\e[33;1mEOF\e[0m")
        $stdin.close
        #reactor.del_input($stdin)
      when /^\/(\S+)\s*(.*)$/ then cmds.fetch($1.to_sym, lambda { |*args|
        puts("\e[33mUnknown command: #{$1}\e[0m")
      }).call(*Shellwords.split($2))
      else
        puts("\e[34m#{line.inspect}\e[0m")
        if client && line =~ /\A\s+\z/
          client.send_msg(key, lines.join("\n"))
          lines = []
        else
          lines << line
        end
      end
    end
    reactor << reader

    $stderr.puts("Running")    
    reactor.serve!
  when /-*help/ then # Prints a list of commands.
    SG::SelfHelp.print
  else raise "Unknown command"
  end
end
