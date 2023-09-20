# coding: utf-8
require 'io/console'

module SG
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
end

