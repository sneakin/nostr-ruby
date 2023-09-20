# coding: utf-8
module SG::Nostr
  class Connection
    extend Forwardable
    attr_reader :websocket
    def_delegators :websocket, :io, :close, :closed?
    
    def initialize websocket
      @websocket = websocket
    end
    
    def read_frames &cb
      return to_enum(__method__) unless cb
      
      websocket.read_frames do |frame|
        if frame.opcode == :text || frame.opcode == :binary
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
      websocket.send_text(JSON.dump([ 'EVENT', msg ? msg.to_h : opts ]))
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
      websocket.send_text(JSON.dump(payload))
    end
    
    def close_req id
      websocket.send_text(JSON.dump([ 'CLOSE', id ]))
    end

    def self.connect *args, **opts
      ws, resp = SG::WebSocket.connect(*args, **opts)
      return new(ws), resp
    end
  end
end
