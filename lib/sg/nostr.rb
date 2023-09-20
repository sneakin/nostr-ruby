#!/usr/bin/env -S bundle exec ruby
# coding: utf-8

require 'json'
require 'openssl'
require 'digest/sha2'
require 'schnorr'
require 'ecdsa'
require 'securerandom'
require 'bech32'
require 'unicode/display_width/string_ext'
require 'forwardable'
require 'optionparser'

require 'sg/hex'
require 'sg/core_ext'
require 'sg/web_socket'

module SG::Nostr
end

require_relative 'nostr/frames'
require_relative 'nostr/private_key'
require_relative 'nostr/public_key'
require_relative 'nostr/message'
require_relative 'nostr/connection'

