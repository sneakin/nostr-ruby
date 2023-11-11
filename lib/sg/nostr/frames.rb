require 'sg/ext'

using SG::Ext

module SG::Nostr
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
  
end
