Gem::Specification.new do |s|
  s.name        = 'nostr'
  s.version     = '0.1.0'
  s.licenses    = ['MIT']
  s.summary     = "A nostr library"
  #s.description = "Much longer explanation of the example!"
  s.authors     = ["Nolan Eakins <sneakin@semanticgap.com>"]
  s.email       = 'support@semanticgap.com'
  s.files       = [ "lib/**/*.rb" ]
  s.homepage    = 'https://oss.semanticgap.com/ruby/nostr'
  s.metadata    = {
    "source_code_uri" => "https://github.com/sneakin/nostr"
  }
  # s.executables = [ 'demos/banner.rb', 'demos/charmap.rb', 'demos/ticker.rb' ]
  s.require_paths = [ 'lib' ]
  s.add_runtime_dependency 'rake'
  s.add_dependency 'bech32'
  s.add_dependency 'unicode-display_width'
  s.add_dependency 'unicode-emoji'
  s.add_dependency 'bip-schnorr'
  #s.add_dependency 'webrick'
end
