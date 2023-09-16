require 'socket'
require 'json'
require 'openssl'
require 'digest/sha2'
require 'base64'
require 'uri'
require 'schnorr'
require 'ecdsa'
require 'securerandom'
require 'bech32'

module Hex
  def self.dehex str
    [ str ].pack('H*')
  end
  
  def self.hex str
    str.unpack('H*').first
  end
end

class Hash
  def symbolize_keys
    self.class[self.collect { |k, v| [ k.to_sym, v ] }]
  end
  def stringify_keys
    self.class[self.collect { |k, v| [ k.to_s, v ] }]
  end
end

class Integer
  def nth_byte byte
    (self >> (byte * 8)) & 0xFF
  end
    
  # todo unused
  def self.revbits bits = 32
    bits.times.reduce(0) do |a, i|
      a | (((self >> i) & 1) << (bits-1-i))
    end
  end
end

class WebSocket
  class ConnectError < RuntimeError; end
  
  attr_reader :io
  
  def initialize io
    @io = io
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
    wait_for_input
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
    i,o,e = IO.select([@io], [], [], timeout)
    i[0] == @io
  end

  # todo could use a line reader like stdin  
  def read_http_response
    lines = []
    begin
      line = @io.readline
      break unless line && !line.empty? && line != "\r\n"
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
        to_read = frame ? frame.length - frame.payload.size : 4096
        rest += io.read_nonblock(to_read)
      else
        @rest = more
        return frame
      end
    end while rest != ''
  rescue IO::EAGAINWaitReadable, OpenSSL::SSL::SSLErrorWaitReadable
    @rest = rest
    nil
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
    io.write(frame.pack)
    io.flush
    self
  end
    
  def send_text payload
    send_frame(Frame.new(opcode: :text, mask: rand(0xFFFFFFFF), payload: payload))
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

class NostrSocket < WebSocket
  # {
  #   "id": <32-bytes lowercase hex-encoded sha256 of the serialized event data>,
  #   "pubkey": <32-bytes lowercase hex-encoded public key of the event creator>,
  #   "created_at": <unix timestamp in seconds>,
  #   "kind": <integer between 0 and 65535>,
  #   "tags": [
  #     [<arbitrary string>...],
  #     ...
  #   ],
  #   "content": <arbitrary string>,
  #   "sig": <64-bytes lowercase hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field>
  # }
  def event msg = nil, **opts
    send_text(JSON.dump([ 'EVENT', msg ? msg.to_h : opts ]))
  end
  
  # {
  # "ids": <a list of event ids>,
  # "authors": <a list of lowercase pubkeys, the pubkey of an event must be one of these>,
  # "kinds": <a list of a kind numbers>,
  # "#<single-letter (a-zA-Z)>": <a list of tag values, for #e — a list of event ids, for #p — a list of event pubkeys etc>,
  # "since": <an integer unix timestamp in seconds, events must be newer than this to pass>,
  # "until": <an integer unix timestamp in seconds, events must be older than this to pass>,
  # "limit": <maximum number of events relays SHOULD return in the initial query>
  # }
  def open_req id, **filters
    send_text(JSON.dump([ 'REQ', id, filters ]))
  end
  
  def close_req id
    send_text(JSON.dump([ 'CLOSE', id ]))
  end

  class Frame
    attr_reader :frame
    
    def initialize frame
      @frame = frame
    end
    
    def js
      @js ||= JSON.load(@frame.payload)
    end
    
    def method_missing mid, *a, **o, &cb
      @frame.send(mid, *a, **o, &cb)
    end
    
    def event_type
      js[0]
    end
    
    def payload
      @payload ||= case event_type
        when 'EVENT' then Message.new(req: js[1], **js[2].symbolize_keys)
        when 'EOSE' then Eose.new(js[1])
        else js
      end
    end    
  end

  class Eose
    attr_reader :req
    
    def initialize req
      @req = req
    end
  end
    
  # OpenSSL examples: https://gist.github.com/ostinelli/1770a93d5c01376728c9
  
  class PrivateKey
    attr_reader :secret, :public_key
    
    def initialize secret, pub = nil
      @secret = secret
      @public_key = case pub
        when PublicKey then pub
        when nil then PublicKey.from_private(secret)
        else PublicKey.new(pub)
        end
    end
    
    def hexdigest
      @secret.to_s(16).rjust(64, '0')
    end
    
    def digest
      ECDSA::Format::IntegerOctetString.encode(@secret, 32)
    end
    
    def sign msg
      Schnorr.sign(msg, digest, SecureRandom.bytes(32)).encode
    end
    
    def verify msg, sig
      Schnorr.valid_sig?(msg, digest, sig)
    end

    def self.generate group = ECDSA::Group::Secp256k1
      priv = nil
      pub = nil
      begin
        priv = 1 + SecureRandom.random_number(group.order - 1)
        pub = PublicKey.from_private(priv, group)
      end until pub.even?
      
      self.new(priv, pub)
    end
    
    def self.load str
      case str
      when /^nsec/ then new(Bech32::Nostr::NIP19.decode(str).data.to_i(16))
      when String then new(str.to_i(16))
      when Integer then new(str)
      else nil
      end
    end
  end
  
  class PublicKey
    attr_reader :key

    def self.from_private priv, group = ECDSA::Group::Secp256k1
      self.new(group.generator.multiply_by_scalar(priv))
    end
        
    def self.load str
      case str
      when /^npub/ then new(Bech32::Nostr::NIP19.decode(str).data)
      when String then new(str)
      when ECDSA::Point then new(str)
      else nil
      end
    end

    def initialize bytes
      @key = if String === bytes # todo rely on #load
         ECDSA::Format::PointOctetString.decode(Hex.dehex(bytes), ECDSA::Group::Secp256k1)
      else
        bytes
      end
    end
    
    def even?
      @key.y.even?
    end
    
    def hexdigest
      Hex.hex(digest)
    end
    
    def digest
      ECDSA::Format::PointOctetString.encode(@key, compression: true)[-32,32]
    end
    
    def make_ssl_key bytes
      group = OpenSSL::PKey::EC::Group.new('secp256k1')
      key = OpenSSL::PKey::EC.new(group)
      public_key_bn = OpenSSL::BN.new("02" + bytes, 16)
      public_key = OpenSSL::PKey::EC::Point.new(group, public_key_bn)
      key.public_key = public_key
      @key = key
    end
    
    def verify msg, sig
      Schnorr.valid_sig?(msg, digest, sig)
    end
  end
  
  class Message
    attr_accessor :id, :pubkey, :created_at, :kind, :tags, :content, :sig
    attr_reader :req
    
    def initialize req: nil, id: nil, pubkey: nil, created_at: nil, kind: nil, tags: nil, content: nil, sig: nil
      @req = req
      @id = id
      @pubkey = String === pubkey ? PublicKey.new(pubkey) : pubkey
      @created_at = created_at
      @kind = kind
      @tags = tags || []
      @content = content
      @sig = sig
    end

    def to_h
      { id: id,
        pubkey: pubkey.hexdigest,
        created_at: created_at.to_i,
        kind: kind,
        tags: tags,
        content: content,
        sig: sig
      }
    end
    
    def to_json
      JSON.dump(to_h)
    end
        
    def canonical_form
      [ 0, pubkey.hexdigest[-64, 64], (created_at || 0).to_i, (kind || 0).to_i, tags, content.to_s ]
    end
    
    def canonical_json
      JSON.dump(canonical_form)
    end
    
    def hexdigest
      Digest::SHA256.hexdigest(canonical_json)
    end
    
    def digest
      Digest::SHA256.digest(canonical_json)
    end
    
    def sign! key
      @pubkey = key.public_key
      @id = hexdigest
      s = key.sign(Hex.dehex(@id))
      @sig = Hex.hex(s.encode)
      self
    end
    
    def verify
      @pubkey.verify(Hex.dehex(id || hexdigest), Hex.dehex(@sig))
    end
  end
  
  def read_frames &cb
    return to_enum(__method__) unless cb
    
    super do |frame|
      if frame.opcode == :text
        if frame.payload[0] == '[' && frame.payload[-1] == ']'
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

if $0 == __FILE__
  # todo one shot REQs to get profile names
  
  uri = ARGV[0] || 'wss://nos.lol/'
  since = (ARGV[1] || 60).to_i
  verbose = ENV.fetch('VERBOSE', '0') != '0'
  private_key = NostrSocket::PrivateKey.load(ENV['KEY']) || NostrSocket::PrivateKey.generate
  
  puts("\e[36;1mKey: %s %s" % [ private_key.hexdigest, Bech32::Nostr::BareEntity.new('nsec', private_key.hexdigest).encode ])
  puts("\e[36;1mPub: %s %s" % [ private_key.public_key.hexdigest, Bech32::Nostr::BareEntity.new('npub', private_key.public_key.hexdigest).encode ])

  s, http_resp = NostrSocket.connect(uri)
  puts("\e[0m", *http_resp)
  short_pub = private_key.public_key.hexdigest[0, 8]
  s.open_req("firehose-#{short_pub}", since: Time.now.to_i - since)
  s.open_req("self-#{short_pub}",
             since: Time.now.to_i - since * since,
             authors: [ private_key.public_key.hexdigest ])

  done = false
  data = ''
  post = nil
  while !done
    i,o,e = IO.select([$stdin, s.io], [], [], 60*60)
    if i.include?($stdin)
      begin
        line = $stdin.read_nonblock(4096)
        pre, blank, post = line.partition(/(?:[\r]?[\n]){2}/)
        if (blank == '' && data[-1] == "\n" && pre =~ /^[\r]?[\n]/)
          blank = "\n\n"
        end
        puts("Read #{pre.inspect} #{blank.inspect} #{post.inspect}")
        data += pre
      rescue IO::EAGAINWaitReadable
      end while blank == ''

      if blank != ''
        m = NostrSocket::Message.new(kind: 1, created_at: Time.now, content: data)
        m.sign!(private_key)
        s.event(**m.to_h)
        data = post || ''
        post = nil
      end
    end

    if i.include?(s.io)
      fr = s.read_frames.to_a
      fr.each do |frame|
        s.pong(frame) if frame.opcode == :ping
        done = true if frame.opcode == :close
        case frame.event_type
        when 'EVENT' then
          puts("\e[35m--- %s" % [ frame.payload.req ],
               "\e[36m%s" % [ Bech32::Nostr::BareEntity.new('note', frame.payload.id).encode ], # bech32 tlsentity
               "\e[%sm%s" % [ frame.payload.verify ? '32' : '31', Bech32::Nostr::BareEntity.new('npub', frame.payload.pubkey.hexdigest).encode ],
               "\e[0m%s" % [ Time.at(frame.payload.created_at) ],
               frame.payload.content)
        else puts("\e[37m" + frame.inspect) if verbose
        end if NostrSocket::Frame === frame
      end
    end
  end

  s.close
end
