require 'socket'
require 'base64'
require 'uri'
require 'openssl'
require 'digest/sha1'
require 'securerandom'
require 'sg/ext'

using SG::Ext

module SG
  class WebSocket
    class ConnectError < RuntimeError; end
    
    attr_accessor :io
    
    def initialize io, init_data: nil
      @io = io
      @rest = init_data
    end
    
    VERSION = 13
    SEC_ACCEPT_SUFFIX = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    
    def greet path, host:
                      wskey = Base64.encode64(SecureRandom.bytes(16)).gsub(/\s+/, '')
      @io.write(<<-EOT % [ path, host, wskey, VERSION ])
GET %s HTTP/1.1
Host: %s
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: %s
Sec-WebSocket-Version: %i

EOT
      @io.flush
      #wait_for_input
      resp = read_http_response
      raise ConnectError.new("Error requesting websocket: #{resp[0]}") unless resp[0] =~ /^HTTP\/1\.1 +101/
      accept_hdr = resp.find { |l| l =~ /^Sec-WebSocket-Accept: (.*)$/i } # todo multiline?
      accept_key = $1.gsub(/\s+/, '')
      resp_key = Base64.encode64(Digest::SHA1.digest(wskey + SEC_ACCEPT_SUFFIX)).gsub(/\s+/, '')
      raise ConnectError.new("Invalid WS key returned") if resp_key != accept_key
      # todo handle redirects and security upgrades
      resp
    end

    def wait_for_input timeout = 1000
      i,o,e = ::IO.select([@io], [], [], timeout)
      i && i[0] == @io
    end

    # todo could use a line reader like stdin  
    def read_http_response
      lines = []
      begin
        line = @io.readline
        break unless line && !line.empty? && !(line =~ /\A[\r]?\n\z/m)
        lines << line
      end while line
      lines
    end

    class Frame
      OpCode = {
        # 0 Continuation frame
        0 => :continue,
        # 1 Text frame
        1 => :text,
        # 2 Binary frame
        2 => :binary,
        # 8 Connection close
        8 => :close,
        # 9 Ping
        9 => :ping,
        # A Pong
        10 => :pong,
        # etc. Reserved
      }

      def self.bits name, attr, shift, mask = 1
        define_method(name) do
          (send(attr) >> shift) & mask
        end
        define_method("#{name}=") do |v|
          if v == true
            v = mask
          elsif v == false || v == nil
            v = 0
          end
          send("#{attr}=", (send(attr) & ~(mask << shift)) | ((v & mask) << shift))
        end
      end
      
      # 0	1	2	3	4	5	6	7	8	9	A	B	C	D	E	F
      # FIN	RSV1	RSV2	RSV3	Opcode	Mask	Payload length
      # Extended payload length (optional)
      # Masking key (optional)
      # Payload data
      # FIN Indicates the final fragment in a message. 1b.
      # RSV MUST be 0 unless defined by an extension. 1b.
      # Opcode Operation code. 4b
      # Mask Set to 1 if the payload data is masked. 1b.
      # Payload length The length of the payload data. 7b.
      # 0-125 This is the payload length.
      # 126 The following 2 bytes are the payload length.
      # 127 The following 8 bytes are the payload length.
      # Masking key All frames sent from the client should be masked by this key. This field is absent if the mask bit is set to 0. 4B.
      # Payload data The payload data of the fragment.  
      
      attr_accessor :header, :mask, :payload
      bits :fin, :header, 15
      bits :rsv1, :header, 14
      bits :rsv2, :header, 13
      bits :rsv3, :header, 12
      bits :opcode_bits, :header, 8, 0xF
      bits :masking, :header, 7
      bits :length0, :header, 0, 0x7F

      def initialize payload: nil, fin: true, opcode: nil, mask: nil
        @header = 0
        @length = 0
        self.fin = fin
        self.opcode = opcode || :text
        self.masking = mask != nil
        @mask = mask
        self.payload = payload || ''
      end
      
      def mask_string str, mask = @mask
        str.unpack('C*').each.with_index.
          collect { |v, i| v ^ mask.nth_byte(3 - (i & 3)) }.
          pack('C*')
      end

      def opcode
        OpCode[opcode_bits]
      end
      
      def opcode= sym
        self.opcode_bits = OpCode.key(sym)
      end
      
      def length
        @length
      end
      
      def length= n
        if n > 0xFFFF
          self.length0 = 127
        elsif n > 127
          self.length0 = 126
        else
          self.length0 = n
        end
        @length = n
      end
      
      def payload= v
        self.length = v.size
        @payload = v
      end
      
      def pack
        packing = 'S>'
        arr = [ header ]
        if length > 127
          arr << length
          if length > 0xFFFF
            packing += 'Q>'
          else
            packing += 'S>'
          end
        end
        if masking != 0
          arr << mask
          packing += 'L>'
          arr << mask_string(payload, mask)
          packing += "a#{@length}"
        else
          arr << payload
          packing += "a#{@length}"
        end
        arr.pack(packing)
      end
      
      def unpack! str
        @header, rest = str.unpack('S>a*')
        return [ nil, str ] if @header == nil

        case length0
        when 126 then @length, rest = rest.unpack('S>a*')
        when 127 then @length, rest = rest.unpack('Q>a*')
        else @length = length0
        end
        return [ nil, str ] if @length == nil
        
        if masking != 0
          @mask, rest = rest.unpack('L>a*')
          if length > 0
            raw, rest = rest.unpack("a#{@length}a*")
            return [ nil, str ] if @mask == nil || raw == nil || raw.size < @length
            @payload = mask_string(raw, @mask)
          end
        elsif length > 0
          @payload, rest = rest.unpack("a#{@length}a*")
          return [ nil, str ] if @payload == nil || @payload.size < @length
        end
        
        return [ self, rest ]
      end
      
      def self.unpack str
        self.new.unpack!(str)
      end
    end
    
    def read_frame
      rest = @rest || ''
      begin
        frame, more = Frame.unpack(rest)
        if frame == nil || frame.length != frame.payload.size
          to_read = frame ? frame.length - frame.payload.size : 8192
          data = io.read_nonblock(to_read)
          #$stderr.puts("#{self.object_id} read_frame: #{data.inspect}")
          rest += data
        else
          @rest = more
          return frame
        end
      end while rest != ''
    rescue ::IO::WaitReadable, ::OpenSSL::SSL::SSLErrorWaitReadable
      @rest = rest
      nil
    rescue
      @rest = rest
      raise
    end
    
    def read_frames &cb
      return to_enum(__method__) unless cb
      
      fragments = @fragments || []
      
      while frame = read_frame
        if frame.fin == 1
          if frame.opcode == 0 && !fragments.empty?
            fragments << fragment
            frame = fragments[0].dup.tap { |f|
              f.payload = fragments.collect(&:payload).join
              f.fin = true
            }
            fragments = []
          end
          cb.call(frame)
        else
          if frame.opcode_bits < 8
            fragments << frame
          else
            cb.call(frame)
          end
        end
      end

      @fragments = fragments
      self
    end

    def send_frame frame
      # $stderr.puts("#{self.object_id} send_frame: #{frame.inspect}")
      io.write(frame.pack)
      io.flush
      self
    end
    
    def send_text payload
      send_frame(Frame.new(opcode: :text, mask: rand(0xFFFFFFFF), payload: payload))
    end
    
    def send_binary payload
      send_frame(Frame.new(opcode: :binary, mask: rand(0xFFFFFFFF), payload: payload))
    end
    
    def ping
      send_frame(Frame.new(opcode: :ping, mask: rand(0xFFFFFFFF)))
    end
    
    def pong ping
      send_frame(Frame.new(opcode: :pong, mask: rand(0xFFFFFFFF), payload: ping.payload))
      io.flush
      self
    end
    
    def send_close
      send_frame(Frame.new(opcode: :close, mask: rand(0xFFFFFFFF)))
    end

    def close
      send_close
      io.close
    end
    
    def self.connect host, port = 80, path = '/', ssl: port == 443
      if host =~ /^[^ ]+:/
        host = URI.parse(host)
      end
      if URI === host
        path = host.path
        path = '/' if path.empty?
        ssl = host.scheme == 'wss'
        port = host.port || (ssl ? 443 : 80)
        host = host.host
      end
      tcp = TCPSocket.open(host, port)
      if ssl
        ctx = OpenSSL::SSL::SSLContext.new
        #ctx.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER)
        tcp = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
        tcp.sync_close = true
        tcp.connect
      end
      host = host + ':' + port.to_s if port != 80
      ws = self.new(tcp)
      resp = ws.greet(path, host: host)
      [ ws, resp ]
    end
  end
end  
