#!/usr/bin/env -S bundle exec ruby
# coding: utf-8

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
require 'io/console'
require 'unicode/display_width/string_ext'

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

class String
  def strip_controls
    gsub(/[\x00-\x1F]+/, '')
  end
  
  def strip_escapes
    gsub(/(\e\[?[-0-9;]+[a-zA-Z])/, '')
  end

  def strip_display_only
    strip_escapes.strip_controls
  end

  def screen_size
    # size minus the escapes and control codes with double width chars counted twice
    #VisualWidth.measure(strip_display_only)
    strip_escapes.display_width
  end

  def visual_slice len
    if screen_size < len
      [ self, nil ]
    else
      part = ''
      width = 0
      in_escape = false
      each_char do |c|
        if width >= len
          break
        end
        if c == "\e"
          in_escape = true
        elsif in_escape && (Range.new('a'.ord, 'z'.ord).include?(c.ord) || Range.new('A'.ord, 'Z'.ord).include?(c.ord))
          in_escape = false
        elsif !in_escape
          width += Unicode::DisplayWidth.of(c)
        end
        part += c
      end
      return [ part, self[part.size..-1] ]
    end
  end
  
  def each_visual_slice n, &cb
    return to_enum(__method__, n) unless cb

    if screen_size < n
      cb.call(self)
    else
      rest = self
      begin
        sl, rest = rest.visual_slice(n)
        cb.call(sl)
      end while(rest && !rest.empty?)
    end

    self
  end
  
  def truncate len
    visual_slice(len).first
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
    i && i[0] == @io
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
  def open_req id, *filters, **filter
    payload = [ 'REQ', id ]
    payload << filter unless filter.empty?
    payload += filters unless filters.empty?
    send_text(JSON.dump(payload))
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
        when 'OK' then Okay.new(js[1], js[2], js[3])
        when 'NOTICE' then Notice.new(js[1])
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
    
  class Notice
    attr_reader :msg
    
    def initialize msg
      @msg = msg
    end
  end
    
  class Okay
    attr_reader :event_id, :accepted, :msg
    
    def initialize eid, accepted, msg
      @event_id = eid
      @accepted = accepted
      @msg = msg
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

module Terminstry
  def self.tty_size
    raise 'haha' if ENV['TTYSIZE'] == '1'
    lines, cols = IO.console.winsize
    [ cols, lines ]
  rescue
    [ ENV.fetch('COLUMNS', 80).to_i, ENV.fetch('LINES', 24).to_i ]
  end

  def self.tabbox title, content, size: tty_size, bg: 9, fg: 9, borderbg: 9, borderfg: fg, titlefg: fg
    border = "\e[0;%i;%im" % [ 30 + borderfg, 40 + borderbg ]
    color = "\e[0;%i;%im" % [ 30 + fg, 40 + bg ]
    title_color = "\e[0;%i;%im" % [ 30 + titlefg, 40 + bg ]
    bordcol = "\e[0;%i;%im" % [ 30 + borderfg, 40 + bg ]
    title = title.truncate(size[0] - 4)
    s = []
    s << "\e[0m%s%s\n" % [ border, '▁' * (title.screen_size + 4) ]
    s << "%s▌%s \e[1m%s \e[0m%s▐%s%s\e[0m\n" % [ bordcol, title_color, title, bordcol, border, '▁' * [ 0, (size[0] - title.screen_size - 4) ].max ]
    #parts = content.scan(/[^\n]{0,#{size[0] - 5}}\n?/)
    #$stderr.puts(parts.to_a.inspect)
    parts = []
    content.split("\n").each do |l|
      #VisualWidth.each_width(l, size[0] - 5) do |p|
      l.each_visual_slice(size[0] - 4) do |p|
        parts << p
      end
    end
    s += parts.collect do |l|
      l = l.rstrip
      "%s▌%s %s%s%s▐\e[0m\n" % [ bordcol, color, l, ' ' * [ (size[0] - 3 - l.screen_size), 0 ].max, bordcol ]
    end
    s << '%s%s' % [ border, '▔' * size[0] ]
    s << "\e[0m"
    s.join
  end
end

class Presenter
  attr_accessor :io

  def initialize io
    @io = io
  end

  def msg_panel title, content, **opts
    @io.puts(Terminstry.tabbox(title, content, **opts))
    self
  end

  def info subject, msg = nil, **opts
    msg_panel(msg ? subject : 'Info', msg || subject, fg: 2, **opts)
  end
  
  def warning subject, msg = nil, **opts
    msg_panel(msg ? subject : 'Warning', msg || subject, fg: 3, **opts)
  end

  def notice msg
    msg_panel('Notice', msg, fg: 6)
  end
  
  def note n, profile:, **opts
    pk_hex = n.pubkey.hexdigest
    pk = Bech32::Nostr::BareEntity.new('npub', pk_hex).encode
    msg_panel("%s %s %s" % [ n.kind, (profile['name'] || '').strip_display_only, n.req ],
              "%s\n" % [ Bech32::Nostr::BareEntity.new('note', n.id).encode ] +
              "\e[1;%sm%s\n" % [ n.verify ? '32' : '31', pk ] +
              "%s\n" % [ Time.at(n.created_at) ] +
              n.content.strip_display_only,
              **opts)
  end

  def profile pro, **opts
    msg_panel("Profile: %s" % [ (pro['name'] || '???').strip_display_only ],
              pro.collect { |k, v| "\e[1m%16s\e[0m %s\n" % [ k, v.to_s.strip_display_only ] }.join,
              **opts)
  end
  
  def log *lines
    lines[0] = "\e[0m" + lines[0]
    @io.puts(*lines)
    self
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
  req_fh = "firehose-#{short_pub}"
  req_self = "self-#{short_pub}"
  s.open_req(req_fh, since: Time.now.to_i - since)
  s.open_req(req_self,
             since: Time.now.to_i - since * since,
             authors: [ private_key.public_key.hexdigest ])
  palette = {
    req_fh => 6,
    req_self => 5
  }
  profiles = Hash.new { |h, k| h[k] = Hash.new }

  pres = Presenter.new($stdout)
  done = false
  data = ''
  post = nil
  ping_time = nil
  tries = 0
  while !done
    i,o,e = IO.select([$stdin, s.io], [], [], 60*60)
    if i == nil
      pres.warning("Timed out #{tries}")
      tries += 1
      s.ping
      next
    end
    
    tries = 0
    
    if i.include?($stdin)
      begin
        line = $stdin.read_nonblock(4096)
        pre, blank, post = line.partition(/(?:[\r]?[\n]){2}/)
        if (blank == '' && data[-1] == "\n" && pre =~ /^[\r]?[\n]/)
          data = data[0..-1]
          blank = "\n\n"
          post = pre[1..-1]
        else
          data += pre
        end
        pres.log("Read #{pre.inspect} #{blank.inspect} #{post.inspect}")
      rescue IO::EAGAINWaitReadable
      rescue EOFError
        done = true
      end while blank == ''

      if blank != ''
        if data =~ /^\/ping/
          s.ping
          ping_time = Time.now
        else
          m = NostrSocket::Message.new(kind: 1, created_at: Time.now, content: data)
          m.sign!(private_key)
          s.event(**m.to_h)
        end
        data = post || ''
        post = nil
      end
    end

    if i.include?(s.io)
      fr = s.read_frames.to_a
      fr.each do |frame|
        case frame.opcode
        when :ping then s.pong(frame)
        when :close then done = true
        when :pong then
          pres.info("Pong", "%i ms" % [ ping_time ? (Time.now - ping_time) * 1000 : -1 ])
          ping_time = nil
        when :text, :binary then
          case frame.event_type
          when 'EOSE' then
            pres.log("EOSE #{frame.payload.req}")
          when 'NOTICE' then
            pres.notice(frame.payload.msg)
          when 'EVENT' then
            pk_hex = frame.payload.pubkey.hexdigest
            if frame.payload.kind == 0 && frame.payload.req =~ /^profile/
              profiles[pk_hex].merge!(JSON.load(frame.payload.content))
              s.close_req(frame.payload.req)
              pres.profile(profiles[pk_hex], borderfg: palette[frame.payload.req] || 7) # bg: palette[frame.payload.req] || 7, fg: 0, borderfg: 7)
            else
              if profiles[pk_hex].empty?
                rn = "profile-#{pk_hex[0,8]}"
                profiles[pk_hex][:req_id] = rn
                pres.log("REQ #{rn}")
                s.open_req(rn, kinds: [ 0 ], authors: [ pk_hex ], limit: 1)
              end
              pres.note(frame.payload, profile: profiles[pk_hex], borderfg: palette[frame.payload.req] || 7) # bg: palette[frame.payload.req] || 7, fg: 0, borderfg: 7)
            end
          else pres.info("Unknown event", frame.inspect, fg: 3, bg: 0) if verbose
          end if NostrSocket::Frame === frame
        else pres.warn("Unknown frame type", frame.inspect,
                       fg: 0, bg: 3)
        end
      end
    end
  end

  s.close
end
