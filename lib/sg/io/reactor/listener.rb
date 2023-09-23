class SG::IO::Reactor
  class Listener < IInput
    def initialize sock, dispatcher, &cb
      super(sock)
      @dispatcher = dispatcher
      @cb = cb || raise(ArgumentError.new('No accept callback block given.'))
    end

    def process
      sock = io.accept
      cin, cout = @cb.call(sock)
      @dispatcher.add_input(cin, sock) if cin
      @dispatcher.add_output(cout, sock) if cout
    end
  end
end
