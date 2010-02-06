#! /usr/bin/env ruby

module Raptcha

  README = <<-__
    NAME
      raptcha.rb

    SYNOPSIS
      super low drain bamage, K.I.S.S., storage-less, session-less,
      plugin-less, zero admin, single-source-file secure captcha system for
      ruby and/or rails.

      bitchin.

    DESCRIPTION
      raptcha manages image generation via a streaming controller.  the result
      is that *no* disk storage is ever needed for captcha images.  it also
      manages authentication via blowfish encoded hidden fields which are
      relayed through the form submission process, obviating the need for
      session/database interaction for captcha validation.  the library is
      useful outside of rails, even from the command line.

      what this means to you is that you can have a nice looking safe captcha
      solution in about 5 minutes that requires zero maintenance moving
      forward.

      see a sample image here
        http://github.com/ahoward/raptcha/blob/master/images/raptcha.png

    INSTALL
      1) SETUP DEPENDENCIES
          - Image Magick system library
          - RMagick gem
          - fattr gem

      2) COPY A SINGLE FILE INTO YOUR RAILS APP
          cp raptcha.rb ./app/lib/

      3) GENERATE THE CONROLLER
          ruby lib/raptcha.rb generate controller

      4) PUT A RAPTCHA IMAGE AND FORM INPUT IN YOUR VIEW
          <%= Raptcha.input %>

      5) REQUIRE VALID RAPTCHA INPUT IN A CONTROLLER ACTION
          class SessionsController < ApplicationController
            def create 
              unless Raptcha.valid?(params)
                # ...
              end
            end
          end

    URIS
      http://github.com/ahoward/raptcha
      http://codforpeople.com


    COMMAND LINE USAGE
      . make an image by hand
        ~> ruby lib/raptcha.rb foreground:pink raptcha.png && open raptcha.png

      . generate the controller
        ~> ruby lib/rapcha.rb generate controller

    DOC
      less raptcha.rb


  __


  Version = '1.0.0' unless defined? Raptcha::Version
  def self.version() Version end

  require 'base64'
  require 'socket'

  begin
    require 'rubygems'
  rescue LoadError
    nil
  end

  begin
    require 'RMagick'
  rescue LoadError
    begin
      require 'Rmagick'
    rescue LoadError
      require 'rmagick'
    end
  end

  require 'fattr'


  module Image
    singleton_class =
      class << self
        self
      end

    singleton_class.module_eval do
      fattr('key'){ "--img--#{ Raptcha.mac_address }--#{ Raptcha.hostname }--"[0,56] }

      fattr('distort'){ Hash[
        :low    => [0, 100],
        :medium => [3, 50],
        :high   => [4, 40],
      ] }

      fattr('default'){ Hash[
        :width       => 150,
        :height      => 50,
        :distort     => :medium,
        #:background  => 'black',
        #:foreground  => 'springgreen',
        :background  => 'white',
        :foreground  => '#ffa500',
        :format      => 'png',
        :font_family => 'monoco',
        :pointsize   => 22,
        :implode     => 0.2,
      ] }


      def create kw = {}
        kw = default.update kw.to_options

        word = kw[:word]
        encrypted = kw[:encrypted] || kw[:e]
        word ||= Raptcha.decrypt(encrypted, :key => key) if encrypted
        word ||= Raptcha.word
        word = word.split(%r"").join(" ")

        kw[:width] = kw[:width].to_i
        kw[:height] = kw[:height].to_i
        kw[:implode] = kw[:implode].to_f

        img = Magick::Image.new(kw[:width], kw[:height]) do |i|
          i.background_color = kw[:background] 
          i.format = kw[:format] 
        end

        draw = Magick::Draw.new

        # text
        draw.stroke = kw[:foreground]
        draw.stroke_width = 0
        draw.font_family = kw[:font_family]
        draw.pointsize = kw[:pointsize]
        #draw.pointsize = kw[:height] * 0.75
        draw.fill = kw[:foreground]
        draw.gravity = Magick::CenterGravity
        draw.annotate img, 0, 0, 5, 5, word

        # lines
        draw.stroke = kw[:foreground]
        draw.stroke_width = 2 
        #draw.line 5, kw[:height]*0.33, kw[:width]-5, kw[:height]*0.33
        #draw.line 5, kw[:height]*0.66, kw[:width]-5, kw[:height]*0.66
        draw.line 5, kw[:height]*0.55, kw[:width]-5, kw[:height]*0.55

        draw.draw img

        img = img.wave *distort[kw[:distort]] 
        img = img.implode kw[:implode] 

        img.to_blob
      end

      def inline kw ={}
        Base64.encode64(create(kw))
      end
    end
  end

  class Error < ::StandardError; end
  class NoInput < Error; end
  class BadInput < Error; end
  class Expired < Error; end

  singleton_class =
    class << self
      self
    end

  singleton_class.module_eval do
    fattr('key'){ "--key--#{ mac_address }--#{ hostname }--"[0,56] }
    fattr('src'){ '/raptcha' }
    fattr('gravity'){ 'north' }
    fattr('hostname'){ Socket.gethostname }
    fattr('user'){ ENV['USER'] || ENV['LOGNAME'] || 'raptcha' }
    fattr('alphabet'){ ('A' .. 'Z').to_a }
    fattr('ttl'){ 30 * 60 }

    fattr('close_enough'){ Hash[
      '0OoQ' => '0',
      '1l'   => '1',
      '2zZ'  => '2',
      '5sS'  => '5',
      'kKxX' => 'x',
    ] }

    def valid? params
      begin
        validate! params
      rescue NoInput 
        nil
      rescue BadInput
        false
      rescue Expired 
        false
      end
    end

    def validate! params
      if params.has_key? 'raptcha'
        raptcha = params['raptcha']

        textarea = raptcha['t']
        word = raptcha['w']
        timebomb = raptcha['b']

        raise NoInput unless textarea and word and timebomb

        word = decrypt word
        timebomb = decrypt timebomb

        begin
          timebomb = Integer timebomb
          timebomb = Time.at(timebomb).utc
          now = Time.now.utc
          raise Expired unless now < timebomb 
        rescue
          raise Expired
        end

        raise BadInput unless fuzzy(word) == fuzzy(textarea)

        textarea
      else
        validate! 'raptcha' => params
      end
    end

    def fuzzy word
      result = word.to_s.downcase
      close_enough.each do |charset, replace|
        result.gsub! %r"[#{ charset }]", replace
      end
      result
    end

    fattr 'input_north'
    fattr 'input_south'
    fattr 'input_east'
    fattr 'input_west'

    def input(kw = {})
      kw.to_options!

      kw[:src] ||= Raptcha.src
      kw[:word] ||= Raptcha.word
      kw[:timebomb] ||= Raptcha.timebomb
      kw[:gravity] ||= Raptcha.gravity

      encrypted_word = encrypt kw[:word], :key => Raptcha.key
      encrypted_timebomb = encrypt kw[:timebomb], :key => Raptcha.key

      west = north = east = south = nil
      case gravity.to_s
        when /w(est)?/
          west = Raptcha.img(kw)
        when /n(orth)?/
          north = Raptcha.img(kw) + '<br>'
        when /e(ast)?/
          east = Raptcha.img(kw)
        when /s(outh)?/
          south = '<br>' + Raptcha.img(kw)
      end

      <<-html
        <div class="raptcha">
          #{ input_north }#{ input_west }
          #{ north } #{ west }
          <input type="textarea" name="raptcha[t]" value="" class="raptcha_t"/>
          <input type="hidden" name="raptcha[w]" value="#{ encrypted_word }" class="raptcha_w"/>
          <input type="hidden" name="raptcha[b]" value="#{ encrypted_timebomb }" class="raptcha_b"/>
          #{ east } #{ south }
          #{ input_east } #{ input_south }
        </div>
      html

    end
    alias_method "tag", "input"

    def img(kw = {})
      kw.to_options!
      return(inline(kw)) if kw[:inline]
      src = kw[:src] || Raptcha.src
      word = kw[:word] || Raptcha.word
      encrypted_word = encrypt word, :key => Image.key
      <<-html
        <img src="#{ src }?e=#{ CGI.escape(encrypted_word) }" alt="raptcha.png" class="raptcha_i"/>
      html
    end

    def inline(kw = {})
      <<-html
        <img src="data:image/png;base64,#{ Image.inline kw  }" alt="raptcha.png" class="raptcha_i"/>
      html
    end

    def timebomb
      Time.now.utc.to_i + Raptcha.ttl
    end

    def word(size = 6)
      w = '' and size.times{ w << alphabet[rand(alphabet.size - 1)]} and w
    end

    def image(*a, &b)
      Raptcha::Image.create(*a, &b)
    end

    def mac_address
      return @mac_address if defined? @mac_address
      re = %r/[^:\-](?:[0-9A-F][0-9A-F][:\-]){5}[0-9A-F][0-9A-F][^:\-]/io
      cmds = '/sbin/ifconfig', '/bin/ifconfig', 'ifconfig', 'ipconfig /all'

      null = test(?e, '/dev/null') ? '/dev/null' : 'NUL'

      lines = nil
      cmds.each do |cmd|
        stdout = IO.popen("#{ cmd } 2> #{ null }"){|fd| fd.readlines} rescue next
        next unless stdout and stdout.size > 0
        lines = stdout and break
      end
      raise "all of #{ cmds.join ' ' } failed" unless lines 

      candidates = lines.select{|line| line =~ re}
      raise 'no mac address candidates' unless candidates.first
      candidates.map!{|c| c[re]}

      maddr = candidates.first
      raise 'no mac address found' unless maddr 

      maddr.strip!
      maddr.instance_eval{ @list = candidates; def list() @list end }

      @mac_address = maddr
    end

    def blowfish
      @blowfish ||= Hash.new{|h,k| h[k] = Crypt::Blowfish.new(k)}
    end

    def encrypt(string, kw = {})
      kw.to_options!
      k = kw[:key] || key 
      Base64.encode64(blowfish[k].encrypt_string(string.to_s)).chop # kill "\n"
    end

    def decrypt(string, kw = {})
      kw.to_options!
      k = kw[:key] || key 
      blowfish[k].decrypt_string(Base64.decode64("#{ string }\n")).strip
    end


    def render(controller, params)
      controller.instance_eval do
        send_data Raptcha.image(params), :type => 'image/png', :disposition => 'inline', :filename => 'raptcha.png'
      end
    end
  end
end




# the command line code
#

  
  module Raptcha
    class Script
      def Script.run
        new.run
      end

      def initialize(argv = ARGV, env = ENV)
        @argv = argv.map{|arg| arg.dup}
        @env = env.to_hash.dup

        @argv, kvs = @argv.partition{|arg| arg !~ /[=:]/}

        @opts = {}
        kvs.each do |kv|
          k, v = kv.split(/[=:]/)
          @opts.update(k.strip => v.strip)
        end

        @mode = @argv.shift || 'help'
      end

      def run
        respond_to?(@mode) ? send(@mode) : send(:help)
      end

      def help
        STDERR.puts(README)
        exit(42)
      end

      def image
        io = @argv.shift || STDOUT
        opened = false
        unless io.respond_to?(:write)
          io = open(io, 'w')
          opened = true
        end
        io.write(Raptcha.image(@opts))
      ensure
        io.close if opened
      end

      def generate
        what = @argv.shift
        send("generate_#{ what }")
      end

      def generate_controller
        src = controller_code
        rails_root = test(?d, 'app') && test(?d, 'app/controllers')

        if rails_root
          path = File.join 'app', 'controllers', 'raptcha_controller.rb'
          if test(?e, path)
            puts "exists #{ path }"
            exit 1
          end
          open(path, 'w'){|fd| fd.puts(src)}
          puts "#{ path }"
        else
          abort 'run this in a RAILS_ROOT'
        end
      end

      def generate_lib
        src = IO.read(__FILE__) 
        rails_root = test(?d, 'app') && test(?d, 'app/controllers')

        if rails_root
          path = File.join('lib', 'raptcha.rb')
          if test(?e, path)
            puts "exists #{ path }"
            exit 1
          end
          open(path, 'w'){|fd| fd.puts(src)}
          puts "#{ path }"
        else
          abort 'run this in a RAILS_ROOT'
        end
      end

      ApplicationController = Class.new unless defined?(ApplicationController)

      ### __CONTROLLER

        class RaptchaController < ApplicationController
        # this is image responder 
        #
          def index
            Raptcha.render(controller=self, params)
          end

        # sample on how to use - you may delete
        #
          def form
            render :inline => <<-html
              <html>
                <body>
                  <hr>
                  <em>valid</em>:#{ Raptcha.valid?(params) ? :true : :false }
                  <hr>
                  <% form_tag do %>
                    #{ Raptcha.input }
                    <hr>
                    <input type=submit name=submit value=submit />
                    <hr>
                    <a href="#{ request.request_uri }">new</a>
                  <% end %>
                </body>
              </html>
            html
          end

        # sample inline image (IE incompatible) - you may delete
        #
          def inline
            render :inline => <<-html
              <html>
                <body>
                  <hr>
                  <em>valid</em>:#{ Raptcha.valid?(params) ? :true : :false }
                  <hr>
                  <% form_tag do %>
                    #{ Raptcha.input :inline => true }
                    <hr>
                    <input type=submit name=submit value=submit />
                    <hr>
                    <a href="#{ request.request_uri }">new</a>
                  <% end %>
                </body>
              </html>
            html
          end
        end

      ### CONTROLLER__

      def controller_code
      # find the code in this source file
      #
        code = []
        open(__FILE__) do |fd|
          inside = false
          while((line = fd.gets))
            break if line =~ /CONTROLLER__/
            code << line if inside
            inside = true if line =~ /__CONTROLLER/
          end
        end

      # un-indent it
      #
        left_margin = nil
        code.each do |line|
          next if line.strip.empty?
          left_margin = line[/^\s+/]
          break if left_margin
        end
        if left_margin and left_margin != 0
          indent = /^\s{#{ left_margin.size }}/
          code.map! do |line|
            line.sub(indent, '')
          end
        end

        code.join
      end
    end
  end

  at_exit{ Raptcha::Script.run } if $0 == __FILE__




# inline the support we need - including the encryption library
#
  BEGIN {

  # hack in a little active_support iff needed
  #
    unless Hash.new.respond_to? 'to_options'
      def to_options
        inject(Hash.new){|h, kv| h.update kv.first.to_s.to_sym => kv.last}
      end

      def to_options!
        h = to_options
        clear
        update h
      end
    end


  # load the fugly-ass embedded encryption library
  #
    open(__FILE__) do |fd|
      while((line = fd.gets))
        break if line.strip == '__END__'
      end
      lineno = fd.lineno
      brutally_fugly_encryption_code = fd.read
      lineno += 1
      eval(brutally_fugly_encryption_code, binding, __FILE__, lineno)
    end
  }



__END__

# cbc.rb  Richard Kernahan <kernighan_rich@rubyforge.org>
module Crypt  #--{{{
module CBC
  
  require 'stringio'
  #require 'crypt/stringxor'
  
  ULONG = 0x100000000
  
  # When this module is mixed in with an encryption class, the class
  # must provide three methods: encrypt_block(block) and decrypt_block(block)
  # and block_size()
  
  
  def generate_initialization_vector(words)
    srand(Time.now.to_i)
    vector = ""
    words.times {
      vector << [rand(ULONG)].pack('N')
    }
    return(vector)
  end
  
  
  def encrypt_stream(plainStream, cryptStream)
    # Cypher-block-chain mode
    
    initVector = generate_initialization_vector(block_size() / 4)
    chain = encrypt_block(initVector)
    cryptStream.write(chain)

    while ((block = plainStream.read(block_size())) && (block.length == block_size()))
      block = block ^ chain 
      encrypted = encrypt_block(block)
      cryptStream.write(encrypted)
      chain = encrypted
    end
   
    # write the final block
    # At most block_size()-1 bytes can be part of the message. 
    # That means the final byte can be used to store the number of meaningful
    # bytes in the final block
    block = '' if block.nil?
    buffer = block.split('')
    remainingMessageBytes = buffer.length
    # we use 7-bit characters to avoid possible strange behavior on the Mac
    remainingMessageBytes.upto(block_size()-2) { buffer << rand(128).chr }
    buffer << remainingMessageBytes.chr
    block = buffer.join('')
    block = block ^ chain
    encrypted = encrypt_block(block)
    cryptStream.write(encrypted)
  end
  
  
  def decrypt_stream(cryptStream, plainStream)
    # Cypher-block-chain mode
    chain = cryptStream.read(block_size())

    while (block = cryptStream.read(block_size()))
      decrypted = decrypt_block(block)
      plainText = decrypted ^ chain
      plainStream.write(plainText) unless cryptStream.eof?
      chain = block
    end
    
    # write the final block, omitting the padding
    buffer = plainText.split('')
    remainingMessageBytes = buffer.last.unpack('C').first
    remainingMessageBytes.times { plainStream.write(buffer.shift) }
  end
  
  
  def carefully_open_file(filename, mode)
    begin
      aFile = File.new(filename, mode)
    rescue
      puts "Sorry. There was a problem opening the file <#{filename}>."
      aFile.close() unless aFile.nil?
      raise
    end
    return(aFile)
  end
  
  
  def encrypt_file(plainFilename, cryptFilename)
    plainFile = carefully_open_file(plainFilename, 'rb')
    cryptFile = carefully_open_file(cryptFilename, 'wb+')
    encrypt_stream(plainFile, cryptFile)
    plainFile.close unless plainFile.closed?
    cryptFile.close unless cryptFile.closed?
  end
  
  
  def decrypt_file(cryptFilename, plainFilename)
    cryptFile = carefully_open_file(cryptFilename, 'rb')
    plainFile = carefully_open_file(plainFilename, 'wb+')
    decrypt_stream(cryptFile, plainFile)
    cryptFile.close unless cryptFile.closed?
    plainFile.close unless plainFile.closed?
  end
  
  
  def encrypt_string(plainText)
    plainStream = StringIO.new(plainText)
    cryptStream = StringIO.new('')
    encrypt_stream(plainStream, cryptStream)
    cryptText = cryptStream.string
    return(cryptText)
  end
  
  
  def decrypt_string(cryptText)
    cryptStream = StringIO.new(cryptText)
    plainStream = StringIO.new('')
    decrypt_stream(cryptStream, plainStream)
    plainText = plainStream.string
    return(plainText)
  end
  
end
end  #--}}}

# blowfish-tables.rb  Richard Kernahan <kernighan_rich@rubyforge.org>
module Crypt  #--{{{
module BlowfishTables
  
    INITIALPARRAY = [
       0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
       0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
       0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
    ]
    
    INITIALSBOXES = [[
      0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
      0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
      0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
      0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
      0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
      0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
      0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
      0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
      0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
      0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
      0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
      0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
      0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
      0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
      0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
      0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
      0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
      0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
      0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b,
      0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
      0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c,
      0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
      0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a,
      0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
      0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
      0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
      0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573, 0x695b27b0, 0xbbca58c8,
      0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
      0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33,
      0x62fb1341, 0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
      0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0,
      0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
      0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777,
      0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 
      0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
      0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
      0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 
      0x226800bb, 0x57b8e0af, 0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 
      0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9, 
      0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915, 
      0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f,
      0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664, 
      0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a], [
      0x4b7a70e9, 0xb5b32944, 
      0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266, 
      0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29, 
      0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 
      0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1, 0x4cdd2086, 0x8470eb26, 
      0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1, 
      0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 
      0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 
      0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9, 0x7ca92ff6, 
      0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7, 
      0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 
      0x3280bba1, 0x183eb331, 0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 
      0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810, 
      0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87, 
      0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa, 
      0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16, 
      0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55, 
      0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509, 
      0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 
      0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 
      0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a, 0xc6150eba, 0x94e2ea78, 
      0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960, 
      0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883, 
      0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
      0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84, 0x1521b628, 0x29076170,
      0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf, 
      0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7,
      0x9cab5cab, 0xb2f3846e, 0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
      0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7, 0x9b540b19, 0x875fa099, 
      0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281, 
      0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263, 
      0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 
      0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3,
      0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0, 
      0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7, 
      0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 
      0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285, 0x095bbf00, 0xad19489d, 
      0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061, 
      0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 
      0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 
      0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc, 0x9e447a2e, 0xc3453484, 
      0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340, 
      0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a, 
      0xe6e39f2b, 0xdb83adf7], [
      0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 
      0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068, 0xd4082471, 0x3320f46a, 
      0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840, 
      0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 
      0x7fac6dd0, 0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 
      0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 
      0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6, 
      0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 
      0xee39d7ab, 0x3b124e8b, 0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 
      0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397, 
      0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b, 
      0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 
      0x5ef47e1c, 0x9029317c, 0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 
      0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 
      0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
      0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e,
      0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 
      0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728, 0xd0127845, 0x95b794fd,
      0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
      0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 
      0x991be14c, 0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 
      0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c, 
      0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb, 
      0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b,
      0x12754ccc, 0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 
      0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386, 
      0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe, 
      0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 
      0x7745ae04, 0xd736fccc, 0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 
      0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 
      0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9, 
      0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 
      0x8cd55591, 0xc902de4c, 0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 
      0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 
      0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169, 
      0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 
      0xa002b5c4, 0x0de6d027, 0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 
      0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62, 0x11e69ed7, 0x2338ea63, 
      0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76, 
      0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 
      0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 
      0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4, 
      0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0], [ 
      0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 
      0xd3822740, 0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 
      0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79, 
      0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6, 
      0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 
      0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
      0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
      0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59, 
      0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797,
      0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
      0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6, 
      0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28, 
      0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba, 
      0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 
      0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5,
      0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f, 
      0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 
      0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 
      0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166, 0xb39a460a, 0x6445c0dd, 
      0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb, 
      0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 
      0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 
      0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc, 
      0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048, 
      0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc, 
      0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 
      0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a, 
      0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f, 
      0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 
      0x0f91fc71, 0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 
      0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 
      0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e, 
      0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e, 
      0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 
      0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623, 
      0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc, 
      0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 
      0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 
      0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b, 0x53113ec0, 0x1640e3d3, 
      0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
      0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c,
      0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
      0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6]
    ]
  

end
end  #--}}}

# blowfish.rb  Richard Kernahan <kernighan_rich@rubyforge.org>
#
#  Blowfish algorithm by Bruce Schneider
#  Ported by Richard Kernahan from the reference C code
module Crypt  #--{{{
class Blowfish
  
  #require 'crypt/cbc'
  include Crypt::CBC
  
  #require 'crypt/blowfish-tables'
  include Crypt::BlowfishTables
  
  ULONG = 0x100000000
  
  def block_size
    return(8)
  end
  
  
  def initialize(key)
    @key = key
    raise "Bad key length: the key must be 1-56 bytes." unless (key.length.between?(1,56))
    @pArray = []
    @sBoxes = []
    setup_blowfish()
  end
  
  
  def f(x)
    a, b, c, d = [x].pack('N').unpack('CCCC')
    y = (@sBoxes[0][a] + @sBoxes[1][b]) % ULONG
    y = (y ^ @sBoxes[2][c]) % ULONG
    y = (y + @sBoxes[3][d]) % ULONG
    return(y)
  end
  
  
  def setup_blowfish()
    @sBoxes = Array.new(4) { |i| INITIALSBOXES[i].clone }
    @pArray = INITIALPARRAY.clone
    keypos = 0
    0.upto(17) { |i|
      data = 0
      4.times {
        data = ((data << 8) | @key[keypos]) % ULONG
        keypos = (keypos.next) % @key.length
      }
      @pArray[i] = (@pArray[i] ^ data) % ULONG
    }
    l = 0
    r = 0
    0.step(17, 2) { |i|
      l, r = encrypt_pair(l, r)
      @pArray[i]   = l
      @pArray[i+1] = r
    }
    0.upto(3) { |i|
      0.step(255, 2) { |j|
        l, r = encrypt_pair(l, r)
        @sBoxes[i][j]   = l
        @sBoxes[i][j+1] = r
      }
    }
  end
  
  def encrypt_pair(xl, xr)
    0.upto(15) { |i|
        xl = (xl ^ @pArray[i]) % ULONG
        xr = (xr ^ f(xl)) % ULONG
        xl, xr = [xl, xr].reverse
    }
    xl, xr = [xl, xr].reverse
    xr = (xr ^ @pArray[16]) % ULONG
    xl = (xl ^ @pArray[17]) % ULONG
    return([xl, xr])
  end
  
  
  def decrypt_pair(xl, xr)
    17.downto(2) { |i|
        xl = (xl ^ @pArray[i]) % ULONG
        xr = (xr ^ f(xl)) % ULONG
        xl, xr = [xl, xr].reverse
    }
    xl, xr = [xl, xr].reverse
    xr = (xr ^ @pArray[1]) % ULONG
    xl = (xl ^ @pArray[0]) % ULONG
    return([xl, xr])
  end
  
  
  def encrypt_block(block)
    xl, xr = block.unpack('NN')
    xl, xr = encrypt_pair(xl, xr)
    encrypted = [xl, xr].pack('NN')
    return(encrypted)
  end
  
  
  def decrypt_block(block)
    xl, xr = block.unpack('NN')
    xl, xr = decrypt_pair(xl, xr)
    decrypted = [xl, xr].pack('NN')
    return(decrypted)
  end
  
end
end  #--}}}

# gost.rb
# Adapted by Richard Kernahan <kernighan_rich@rubyforge.org> 
# from C++ code written by Wei Dai 
# of the Crypto++ project http://www.eskimo.com/~weidai/cryptlib.html
module Crypt #--{{{
class Gost

  #require 'crypt/cbc'
  include CBC
  
  ULONG   = 0x100000000
  
  def block_size
    return(8)
  end
  
  
  def initialize(userKey)
  
    # These are the S-boxes given in Applied Cryptography 2nd Ed., p. 333
    @sBox = [
      [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
      [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
      [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
      [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
      [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
      [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
      [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
      [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
    ]

    # These are the S-boxes given in the GOST source code listing in Applied
	  # Cryptography 2nd Ed., p. 644.  They appear to be from the DES S-boxes
    # [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 ],
    # [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 ],
    # [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 ],
    # [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 ],
    # [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 ],
    # [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 ],
    # [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 ],
    # [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 ] 
    
    # precalculate the S table
    @sTable = precalculate_S_table()
    
    # derive the 32-byte key from the user-supplied key
    userKeyLength = userKey.length
    @key = userKey[0..31].unpack('C'*32)
    if (userKeyLength < 32)
      userKeyLength.upto(31) { @key << 0 }
    end
  end
  
  
  def precalculate_S_table()
    sTable = [[], [], [], []]
    0.upto(3) { |i|
      0.upto(255) { |j|
        t = @sBox[2*i][j % 16] | (@sBox[2*i+1][j/16] << 4)
        u = (8*i + 11) % 32
        v = (t << u) | (t >> (32-u))
        sTable[i][j] = (v % ULONG)
      } 
    }
    return(sTable)
  end
  
  
  def f(longWord)
    longWord = longWord % ULONG
    a, b, c, d = [longWord].pack('L').unpack('CCCC')
    return(@sTable[3][d] ^ @sTable[2][c] ^ @sTable[1][b] ^ @sTable[0][a])
  end
  
  
  def encrypt_pair(xl, xr)
    3.times {
      xr ^= f(xl+@key[0])
      xl ^= f(xr+@key[1])
      xr ^= f(xl+@key[2])
      xl ^= f(xr+@key[3])
      xr ^= f(xl+@key[4])
      xl ^= f(xr+@key[5])
      xr ^= f(xl+@key[6])
      xl ^= f(xr+@key[7])
    }
    xr ^= f(xl+@key[7])
    xl ^= f(xr+@key[6])
    xr ^= f(xl+@key[5])
    xl ^= f(xr+@key[4])
    xr ^= f(xl+@key[3])
    xl ^= f(xr+@key[2])
    xr ^= f(xl+@key[1])
    xl ^= f(xr+@key[0])
    return([xr, xl])
  end
  
  
  def decrypt_pair(xl, xr)
    xr ^= f(xl+@key[0])
    xl ^= f(xr+@key[1])
    xr ^= f(xl+@key[2])
    xl ^= f(xr+@key[3])
    xr ^= f(xl+@key[4])
    xl ^= f(xr+@key[5])
    xr ^= f(xl+@key[6])
    xl ^= f(xr+@key[7])
    3.times {
      xr ^= f(xl+@key[7])
      xl ^= f(xr+@key[6])
      xr ^= f(xl+@key[5])
      xl ^= f(xr+@key[4])
      xr ^= f(xl+@key[3])
      xl ^= f(xr+@key[2])
      xr ^= f(xl+@key[1])
      xl ^= f(xr+@key[0])
    }
    return([xr, xl])
  end
  
  
  def encrypt_block(block)
    xl, xr = block.unpack('NN')
    xl, xr = encrypt_pair(xl, xr)
    encrypted = [xl, xr].pack('NN')
    return(encrypted)
  end
  
  
  def decrypt_block(block)
    xl, xr = block.unpack('NN')
    xl, xr = decrypt_pair(xl, xr)
    decrypted = [xl, xr].pack('NN')
    return(decrypted)
  end


end
end  #--}}}

# idea.rb  Richard Kernahan <kernighan_rich@rubyforge.org>
# IDEA (International Data Encryption Algorithm) by 
# Xuejia Lai and James Massey (1992).  Refer to license info at end.
# Ported by Richard Kernahan 2005
module Crypt  #--{{{
class IDEA
  
  #require 'crypt/cbc'
  include Crypt::CBC

  require 'digest/md5'
  
  ULONG   = 0x100000000
  USHORT  = 0x10000
  
  ENCRYPT = 0
  DECRYPT = 1
  
  
  def block_size
    return(8)
  end
  
  
  def initialize(key128, mode)
    # IDEA is subject to attack unless the key is sufficiently random, so we
    # take an MD5 digest of a variable-length passphrase to ensure a solid key
    if (key128.class == String)  
      digest = Digest::MD5.new(key128).digest
      key128 = digest.unpack('n'*8)
    end
    raise "Key must be 128 bits (8 words)" unless (key128.class == Array) && (key128.length == 8)
    raise "Mode must be IDEA::ENCRYPT or IDEA::DECRYPT" unless ((mode == ENCRYPT) | (mode == DECRYPT))
    if (mode == ENCRYPT)
      @subkeys = generate_encryption_subkeys(key128)
    else (mode == DECRYPT)
      @subkeys = generate_decryption_subkeys(key128)
    end
  end
  
  
  def mul(a, b)
    modulus = 0x10001
    return((1 - b) % USHORT) if (a == 0)
    return((1 - a) % USHORT) if (b == 0)
    return((a * b) % modulus)
  end
  
  
  def mulInv(x)
    modulus = 0x10001
    x = x.to_i % USHORT
    return(x) if (x <= 1)
    t1 = USHORT / x
    y  = modulus % x
    if (y == 1)
      inv = (1 - t1) & 0xFFFF
      return(inv)
    end
    t0 = 1
    while (y != 1)
      q = x / y
      x = x % y
      t0 = t0 + (q * t1)
      return(t0) if (x == 1)
      q = y / x
      y = y % x
      t1 = t1 + (q * t0)
    end
    inv = (1 - t1) & 0xFFFF
    return(inv)
  end
  
  
  def generate_encryption_subkeys(key)
    encrypt_keys = []
    encrypt_keys[0..7] = key.dup
    8.upto(51) { |i|
      a = ((i + 1) % 8 > 0) ? (i-7)  : (i-15)
      b = ((i + 2) % 8 < 2) ? (i-14) : (i-6)
      encrypt_keys[i] = ((encrypt_keys[a] << 9) | (encrypt_keys[b] >> 7)) % USHORT
    }
    return(encrypt_keys)
  end
  
  
  def generate_decryption_subkeys(key)
    encrypt_keys = generate_encryption_subkeys(key)
    decrypt_keys = []
    decrypt_keys[48] = mulInv(encrypt_keys.shift)
    decrypt_keys[49] = (-encrypt_keys.shift) % USHORT
    decrypt_keys[50] = (-encrypt_keys.shift) % USHORT
    decrypt_keys[51] = mulInv(encrypt_keys.shift)
    42.step(0, -6) { |i|
      decrypt_keys[i+4] = encrypt_keys.shift % USHORT
      decrypt_keys[i+5] = encrypt_keys.shift % USHORT
      decrypt_keys[i]   = mulInv(encrypt_keys.shift)
      if (i ==0)
        decrypt_keys[1] = (-encrypt_keys.shift) % USHORT
        decrypt_keys[2] = (-encrypt_keys.shift) % USHORT
      else
        decrypt_keys[i+2] = (-encrypt_keys.shift) % USHORT
        decrypt_keys[i+1] = (-encrypt_keys.shift) % USHORT
      end
      decrypt_keys[i+3] = mulInv(encrypt_keys.shift)
    }
    return(decrypt_keys)
  end
  
  
  def crypt_pair(l, r)
    word = [l, r].pack('NN').unpack('nnnn')
    k = @subkeys[0..51]
    8.downto(1) { |i|
      word[0] = mul(word[0], k.shift)
      word[1] = (word[1] + k.shift) % USHORT
      word[2] = (word[2] + k.shift) % USHORT
      word[3] = mul(word[3], k.shift)
      t2 = word[0] ^ word[2]
      t2 = mul(t2, k.shift)
      t1 = (t2 + (word[1] ^ word[3])) % USHORT
      t1 = mul(t1, k.shift)
      t2 = (t1 + t2) % USHORT
      word[0] ^= t1
      word[3] ^= t2
      t2 ^= word[1]
      word[1] = word[2] ^ t1
      word[2] = t2
    }
    result = []
    result << mul(word[0], k.shift)
    result << (word[2] + k.shift) % USHORT
    result << (word[1] + k.shift) % USHORT
    result << mul(word[3], k.shift)
    twoLongs = result.pack('nnnn').unpack('NN')
    return(twoLongs)
  end
  
  def encrypt_block(block)
    xl, xr = block.unpack('NN')
    xl, xr = crypt_pair(xl, xr)
    encrypted = [xl, xr].pack('NN')
    return(encrypted)
  end
  
  
  def decrypt_block(block)
    xl, xr = block.unpack('NN')
    xl, xr = crypt_pair(xl, xr)
    decrypted = [xl, xr].pack('NN')
    return(decrypted)
  end


end
end  #--}}}

# LICENSE INFORMATION
#
# This software product contains the IDEA algorithm as described and claimed in
# US patent 5,214,703, EPO patent 0482154 (covering Austria, France, Germany,
# Italy, the Netherlands, Spain, Sweden, Switzerland, and the UK), and Japanese
# patent application 508119/1991, "Device for the conversion of a digital block
# and use of same" (hereinafter referred to as "the algorithm").  Any use of
# the algorithm for commercial purposes is thus subject to a license from Ascom
# Systec Ltd. of CH-5506 Maegenwil (Switzerland), being the patentee and sole
# owner of all rights, including the trademark IDEA.
# 
# Commercial purposes shall mean any revenue generating purpose including but
# not limited to:
# 
# i) Using the algorithm for company internal purposes (subject to a site
#    license).
# 
# ii) Incorporating the algorithm into any software and distributing such
#     software and/or providing services relating thereto to others (subject to
#     a product license).
# 
# iii) Using a product containing the algorithm not covered by an IDEA license
#      (subject to an end user license).
# 
# All such end user license agreements are available exclusively from Ascom
# Systec Ltd and may be requested via the WWW at http://www.ascom.ch/systec or
# by email to idea@ascom.ch.
# 
# Use other than for commercial purposes is strictly limited to non-revenue
# generating data transfer between private individuals.  The use by government
# agencies, non-profit organizations, etc is considered as use for commercial
# purposes but may be subject to special conditions.  Any misuse will be
# prosecuted.

# crypt/rattle.rb  Richard Kernahan <kernighan_rich@rubyforge.org>

# add_noise - take a message and intersperse noise to make a new noisy message of given byte-length
# remove_noise - take a noisy message and extract the message
module Crypt  #--{{{
module Noise

  def add_noise(newLength)
    message = self
    usableNoisyMessageLength = newLength / 9 * 8
    bitmapSize = newLength / 9
    remainingBytes = newLength - usableNoisyMessageLength - bitmapSize
    if (message.length > usableNoisyMessageLength)
      minimumNewLength = (message.length / 8.0).ceil * 9
      puts "For a clear text of #{message.length} bytes, the minimum obscured length"
      puts "is #{minimumNewLength} bytes which allows for no noise in the message."
      puts "You should choose an obscured length of at least double the clear text"
      puts "length, such as #{message.length / 8 * 32} bytes"
      raise "Insufficient length for noisy message" 
    end
    bitmap = []
    usableNoisyMessageLength.times { bitmap << false }
    srand(Time.now.to_i)
    positionsSelected = 0
    while (positionsSelected < message.length)
      positionTaken = rand(usableNoisyMessageLength)
      if bitmap[positionTaken]
        next
      else
        bitmap[positionTaken] = true
        positionsSelected = positionsSelected.next
      end
    end
    
    noisyMessage = ""
    0.upto(bitmapSize-1) { |byte|
      c = 0
      0.upto(7) { |bit|
        c = c + (1<<bit) if bitmap[byte * 8 + bit]
      }
      noisyMessage << c.chr
    }
    posInMessage = 0
    0.upto(usableNoisyMessageLength-1) { |pos|
      if bitmap[pos]
        meaningfulByte = message[posInMessage]
        noisyMessage << meaningfulByte
        posInMessage = posInMessage.next
      else
        noiseByte = rand(256).chr
        noisyMessage << noiseByte
      end
    }
    remainingBytes.times {
        noiseByte = rand(256).chr
        noisyMessage << noiseByte
    }
    return(noisyMessage)
  end
  
  
  def remove_noise
    noisyMessage = self
    bitmapSize = noisyMessage.length / 9
    actualMessageLength =  bitmapSize * 8
    
    actualMessageStart = bitmapSize
    actualMessageFinish = bitmapSize + actualMessageLength - 1
    actualMessage = noisyMessage[actualMessageStart..actualMessageFinish]
    
    bitmap = []
    0.upto(bitmapSize - 1) { |byte|
      c = noisyMessage[byte]
      0.upto(7) { |bit|
        bitmap[byte * 8 + bit] = (c[bit] == 1)
      }
    }
    clearMessage = ""
    0.upto(actualMessageLength) { |pos|
      meaningful = bitmap[pos]
      if meaningful
        clearMessage << actualMessage[pos]
      end
    }
    return(clearMessage)
  end
  
end
end

class String
  include Crypt::Noise
end  #--}}}


# Thanks to Binky DaClown who wrote this pure-ruby implementation 
# http://rubyforge.org/projects/prstringio/
# Apparently CBC does not work well with the C-based stringio
module Crypt  #--{{{
class PureRubyStringIO

	include Enumerable

	SEEK_CUR = IO::SEEK_CUR
	SEEK_END = IO::SEEK_END
	SEEK_SET = IO::SEEK_SET

	@@relayMethods = [:<<, :all?, :any?, :binmode, :close, :close_read, :close_write, :closed?, :closed_read?,
	                  :closed_write?, :collect, :detect, :each, :each_byte, :each_line, :each_with_index,
	                  :entries, :eof, :eof?, :fcntl, :fileno, :find, :find_all, :flush, :fsync, :getc, :gets,
	                  :grep, :include?, :inject, :isatty, :length, :lineno, :lineno=, :map, :max, :member?,
	                  :min, :partition, :path, :pid, :pos, :pos=, :print, :printf, :putc, :puts, :read,
	                  :readchar, :readline, :readlines, :reject, :rewind, :seek, :select, :size, :sort,
	                  :sort_by, :string, :string=, :sync, :sync=, :sysread, :syswrite, :tell, :truncate, :tty?,
	                  :ungetc, :write, :zip]

	def self.open(string="", mode="r+")
		if block_given? then
			sio = new(string, mode)
			rc = yield(sio)
			sio.close
			rc
		else
			new(string, mode)
		end
	end

	def <<(obj)
		requireWritable
		write obj
		self
	end

	def binmode
		self
	end

	def close
		requireOpen
		@sio_closed_read = true
		@sio_closed_write = true
		self
	end

	def close_read
		raise IOError, "closing non-duplex IO for reading", caller if closed_read?
		@sio_closed_read = true
		self
	end

	def close_write
		raise IOError, "closing non-duplex IO for writing", caller if closed_write?
		@sio_closed_read = true
		self
	end

	def closed?
		closed_read? && closed_write?
	end

	def closed_read?
		@sio_closed_read
	end

	def closed_write?
		@sio_closed_write
	end

	def each(sep_string=$/, &block)
		requireReadable
		@sio_string.each(sep_string, &block)
		@sio_pos = @sio_string.length
	end

	def each_byte(&block)
		requireReadable
		@sio_string.each_byte(&block)
		@sio_pos = @sio_string.length
	end

	def eof
		requireReadable { @sio_pos >= @sio_string.length }
	end

	def fcntl(integer_cmd, arg)
		raise NotImplementedError, "The fcntl() function is unimplemented on this machine", caller
	end

	def fileno
		nil
	end

	def flush
		self
	end

	def fsync
		0
	end

	def getc
		requireReadable
		char = @sio_string[@sio_pos]
		@sio_pos +=  1 unless char.nil?
		char
	end

	def gets(sep_string=$/)
		requireReadable
		@sio_lineno += 1
		pstart = @sio_pos
		@sio_pos = @sio_string.index(sep_string, @sio_pos) || [@sio_string.length, @sio_pos].max
		@sio_string[pstart..@sio_pos]
	end

	def initialize(string="", mode="r+")
		@sio_string = string.to_s
		@sio_lineno = 0
		@mode = mode
		@relay = nil
		case mode.delete("b")
		when "r"
			@sio_closed_read = false
			@sio_closed_write = true
			@sio_pos = 0
		when "r+"
			@sio_closed_read = false
			@sio_closed_write = false
			@sio_pos = 0
		when "w"
			@sio_closed_read = true
			@sio_closed_write = false
			@sio_pos = 0
			@sio_string.replace("")
		when "w+"
			@sio_closed_read = false
			@sio_closed_write = false
			@sio_pos = 0
			@sio_string.replace("")
		when "a"
			@sio_closed_read = true
			@sio_closed_write = false
			@sio_pos = @sio_string.length
		when "a+"
			@sio_closed_read = false
			@sio_closed_write = false
			@sio_pos = @sio_string.length
		else
			raise ArgumentError, "illegal access mode #{mode}", caller
		end
	end

	def isatty
		flase
	end

	def length
		@sio_string.length
	end

	def lineno
		@sio_lineno
	end

	def lineno=(integer)
		@sio_lineno = integer
	end

	def path
		nil
	end

	def pid
		nil
	end

	def pos
		@sio_pos
	end

	def pos=(integer)
		raise Errno::EINVAL, "Invalid argument", caller if integer < 0
		@sio_pos = integer
	end

	def print(*args)
		requireWritable
		args.unshift($_) if args.empty
		args.each { |obj| write(obj) }
		write($\) unless $\.nil?
		nil
	end

	def printf(format_string, *args)
		requireWritable
		write format(format_string, *args)
		nil
	end

	def putc(obj)
		requireWritable
		write(obj.is_a?(Numeric) ? sprintf("%c", obj) : obj.to_s[0..0])
		obj
	end

	def puts(*args)
		requireWritable
		args.unshift("") if args.empty?
		args.each { |obj|
			write obj
			write $/
		}
		nil
	end

	def read(length=nil, buffer=nil)
		requireReadable
		len = length || [@sio_string.length - @sio_pos, 0].max
		raise ArgumentError, "negative length #{len} given", caller if len < 0
		buffer ||= ""
		pstart = @sio_pos
		@sio_pos += len
		buffer.replace(@sio_string[pstart..@sio_pos])
		buffer.empty? && !length.nil? ? nil : buffer
	end

	def readchar
		requireReadable
		raise EOFError, "End of file reached", caller if eof?
		getc
	end

	def readline
		requireReadable
		raise EOFError, "End of file reached", caller if eof?
		gets
	end

	def readlines(sep_string=$/)
		requireReadable
		raise EOFError, "End of file reached", caller if eof?
		rc = []
		until eof
			rc << gets(sep_string)
		end
		rc
	end

	def reopen(string, mode=nil)
		if string.is_a?(self.class) then
			raise ArgumentError, "wrong number of arguments (2 for 1)", caller if !mode.nil?
			@relay = string
			instance_eval(%Q{
				class << self
					@@relayMethods.each { |name|
						define_method(name, ObjectSpace._id2ref(#{@relay.object_id}).method(("original_" + name.to_s).to_sym).to_proc)
					}
				end
			})
		else
			raise ArgumentError, "wrong number of arguments (1 for 2)", caller if mode.nil?
			class << self
				@@relayMethods.each { |name|
					alias_method(name, "original_#{name}".to_sym)
					public name
				}
				@relay = nil
			end unless @relay.nil?
			@sio_string = string.to_s
			@mode = mode
		end
	end

	def rewind
		@sio_pos = 0
		@sio_lineno = 0
	end

	def seek(amount, whence=SEEK_SET)
		if whence == SEEK_CUR then
			offset += @sio_pos
		elsif whence == SEEK_END then
			offset += size
		end
		@sio_pos = offset
	end

	def string
		@sio_string
	end
	
	def string=(newstring)
		@sio_string = newstring
	end

	def sync
		true
	end

	def sync=(boolean)
		boolean
	end

	def sysread(length=nil, buffer=nil)
		requireReadable
		raise EOFError, "End of file reached", caller if eof?
		read(length, buffer)
	end

	def syswrite(string)
		requireWritable
		addition = "\000" * (@sio_string.length - @sio_pos) + string.to_s
		@sio_string[@sio_pos..(addition.length - 1)] = addition
		@sio_pos +=  addition.size
		addition.size
	end

	#In ruby 1.8.4 truncate differs from the docs in two ways.
	#First, if an integer greater that the length is given then the string is expanded to the new integer
	#length. As this expansion seems to contain junk characters instead of nulls I suspect this may be a
	#flaw in the C code which could cause a core dump if abused/used.
	#Second, the documentation states that  truncate returns 0. It returns the integer instead.
	#This implementation follows the documentation in the first instance as I suspect this will be fixed
	#in the C code. In the second instance, it follows the actions of the C code instead of the docs.
	#This was decided as it causes no immedeate harm and this ruby implentation is to be as compatable
	#as possible with the C version. Should the C version change to match the docs the ruby version
	#will be simple to update as well. 
	def truncate(integer)
		requireWritable
		raise Errno::EINVAL, "Invalid argument - negative length", caller if integer < 0
		@sio_string[[integer, @sio_string.length].max..-1] = ""
		integer
	end

	def ungetc(integer)
		requireWritable
		if @sio_pos > 0 then
			@sio_pos -= 1
			putc(integer)
			@sio_pos -= 1
		end
	end

	alias :each_line :each
	alias :eof? :eof
	alias :size :length
	alias :tty? :isatty
	alias :tell :pos
	alias :write :syswrite

	protected
	@@relayMethods.each { |name|
		alias_method("original_#{name}".to_sym, name)
		protected "original_#{name}".to_sym
	}

	private

	def requireReadable
		raise IOError, "not opened for reading", caller[1..-1] if @sio_closed_read
	end

	def requireWritable
		raise IOError, "not opened for writing", caller[1..-1] if @sio_closed_write
	end

	def requireOpen
		raise IOError, "closed stream", caller[1..-1] if @sio_closed_read && @sio_closed_write
	end

end
end  #--}}}

# rijndael-tables.rb  Richard Kernahan <kernighan_rich@rubyforge.org>
module Crypt  #--{{{
module RijndaelTables

LogTable = [
  0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3, 
100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193, 
125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120, 
101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142, 
150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56, 
102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16, 
126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186, 
 43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87, 
175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232, 
 44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160, 
127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183, 
204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 
151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209, 
 83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171, 
 68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165, 
103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7
]

AlogTable = [
  1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53, 
 95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170, 
229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49, 
 83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205, 
 76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136, 
131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154, 
181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163, 
254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160, 
251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65, 
195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117, 
159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84, 
252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202, 
 69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14, 
 18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23, 
 57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1
]

S = [
 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118, 
202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21, 
  4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117, 
  9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132, 
 83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207, 
208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168, 
 81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210, 
205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115, 
 96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219, 
224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121, 
231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8, 
186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138, 
112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158, 
225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223, 
140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22
]

Si = [
 82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251, 
124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203, 
 84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78, 
  8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37, 
114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146, 
108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132, 
144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6, 
208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107, 
 58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 
150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110, 
 71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27, 
252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244, 
 31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95, 
 96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239, 
160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97, 
 23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125, 
]

IG = [
[0x0e, 0x09, 0x0d, 0x0b], 
[0x0b, 0x0e, 0x09, 0x0d], 
[0x0d, 0x0b, 0x0e, 0x09], 
[0x09, 0x0d, 0x0b, 0x0e] 
]

Rcon = [ 
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 
  0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 
  0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
]

Shifts = [
  [
     [0, 0],
     [1, 3],
     [2, 2],
     [3, 1]
  ], [  
     [0, 0],
     [1, 5],
     [2, 4],
     [3, 3]
  ], [
     [0, 0],
     [1, 7],
     [3, 5],
     [4, 4]
  ]
]

end
end  #--}}}

# rijndael.rb  Richard Kernahan <kernighan_rich@rubyforge.org>
# Adapted from the reference C implementation:
#   rijndael-alg-ref.c   v2.2   March 2002
#   Reference ANSI C code
#   authors: Paulo Barreto and Vincent Rijmen
#   This code is placed in the public domain.
module Crypt  #--{{{
class Rijndael

  #require 'crypt/cbc'
  include Crypt::CBC
  
  #require 'crypt/rijndael-tables'
  include Crypt::RijndaelTables
  
  
  def initialize(userKey, keyBits = 256, blockBits = 128)
    case keyBits
      when 128 
        @keyWords = 4
      when 192 
        @keyWords = 6
      when 256
        @keyWords = 8
      else raise "The key must be 128, 192, or 256 bits long."
    end
    
    case (keyBits >= blockBits) ? keyBits : blockBits
      when 128 
        @rounds = 10
      when 192 
        @rounds = 12
      when 256
        @rounds = 14
      else raise "The key and block sizes must be 128, 192, or 256 bits long."
    end
   
    case blockBits
      when 128 
        @blockSize = 16
        @blockWords = 4
        @shiftIndex = 0
      when 192 
        @blockSize = 24
        @blockWords = 6
        @shiftIndex = 1
      when 256 
        @blockSize = 32
        @blockWords = 8
        @shiftIndex = 2
      else raise "The block size must be 128, 192, or 256 bits long."
    end
    
    uk = userKey.unpack('C'*userKey.length)
    maxUsefulSizeOfUserKey = (keyBits/8)
    uk = uk[0..maxUsefulSizeOfUserKey-1]    # truncate
    padding = 0
    if (userKey.length < keyBits/8)
      shortfallInUserKey = (keyBits/8 - userKey.length)
      shortfallInUserKey.times { uk << padding }
    end
    @key = [[], [], [], []]
    0.upto(uk.length-1) { |pos|
      @key[pos % 4][pos / 4] = uk[pos]
    }
    @roundKeys = generate_key_schedule(@key, keyBits, blockBits)
  end

  
  def block_size
    return(@blockSize) # needed for CBC
  end
  
  
  def mul(a, b)
    if ((a ==0) | (b == 0))
      result = 0 
    else
      result = AlogTable[(LogTable[a] + LogTable[b]) % 255]
    end
    return(result)
  end
  
  
  def add_round_key(blockArray, roundKey)
  0.upto(3) { |i|
    0.upto(@blockWords) { |j|
      blockArray[i][j] ^= roundKey[i][j]
    }
  }
  return(blockArray)
  end
  
  
  def shift_rows(blockArray, direction)
    tmp = []
    1.upto(3) { |i|  # row zero remains unchanged
      0.upto(@blockWords-1) { |j|
        tmp[j] = blockArray[i][(j + Shifts[@shiftIndex][i][direction]) % @blockWords]
      }
      0.upto(@blockWords-1) { |j|
        blockArray[i][j] = tmp[j]
      }
    }
    return(blockArray)
  end
  
  
  def substitution(blockArray, sBox)
    # replace every byte of the input with the byte at that position in the S-box
    0.upto(3) { |i|
      0.upto(@blockWords-1) { |j|
        blockArray[i][j] = sBox[blockArray[i][j]]
      }
    }
    return(blockArray)
  end
  
  
  def mix_columns(blockArray)
    mixed = [[], [], [], []]
    0.upto(@blockWords-1) { |j|
      0.upto(3) { |i|
        mixed[i][j] = mul(2,blockArray[i][j]) ^
          mul(3,blockArray[(i + 1) % 4][j]) ^
          blockArray[(i + 2) % 4][j] ^
          blockArray[(i + 3) % 4][j]
      }
    }
    return(mixed)
  end
  
  
  def inverse_mix_columns(blockArray)
    unmixed = [[], [], [], []]
    0.upto(@blockWords-1) { |j|
      0.upto(3) { |i|
        unmixed[i][j] = mul(0xe, blockArray[i][j]) ^
          mul(0xb, blockArray[(i + 1) % 4][j]) ^                
          mul(0xd, blockArray[(i + 2) % 4][j]) ^
          mul(0x9, blockArray[(i + 3) % 4][j])
      }
    }
     return(unmixed)
  end
  
  
  def generate_key_schedule(k, keyBits, blockBits)
    tk = k[0..3][0..@keyWords-1]  # using slice to get a copy instead of a reference
    keySched = []
    (@rounds + 1).times { keySched << [[], [], [], []] }
    t = 0
    j = 0
    while ((j < @keyWords) && (t < (@rounds+1)*@blockWords))
      0.upto(3) { |i|
        keySched[t / @blockWords][i][t % @blockWords] = tk[i][j]
      }
      j += 1
      t += 1
    end
    # while not enough round key material collected, calculate new values
    rconIndex = 0
    while (t < (@rounds+1)*@blockWords) 
      0.upto(3) { |i|
        tk[i][0] ^= S[tk[(i + 1) % 4][@keyWords - 1]]
      }
      tk[0][0] ^= Rcon[rconIndex]
      rconIndex = rconIndex.next
      if (@keyWords != 8)
        1.upto(@keyWords - 1) { |j|
          0.upto(3) { |i|
            tk[i][j] ^= tk[i][j-1];
          }
        }
      else
        1.upto(@keyWords/2 - 1) { |j|
          0.upto(3) { |i|
            tk[i][j] ^= tk[i][j-1]
          }
        }
        0.upto(3) { |i|
          tk[i][@keyWords/2] ^= S[tk[i][@keyWords/2 - 1]]
        }
        (@keyWords/2 + 1).upto(@keyWords - 1) { |j|
          0.upto(3) { |i| 
            tk[i][j] ^= tk[i][j-1] 
          }
        }
      end
      j = 0
      while ((j < @keyWords) && (t < (@rounds+1) * @blockWords))
        0.upto(3) { |i|
          keySched[t / @blockWords][i][t % @blockWords] = tk[i][j]
        }
        j += 1
        t += 1
      end
    end
    return(keySched)
  end
  
  
  def encrypt_byte_array(blockArray)
    blockArray = add_round_key(blockArray, @roundKeys[0])
    1.upto(@rounds - 1) { |round|
      blockArray = substitution(blockArray, S)
      blockArray = shift_rows(blockArray, 0)
      blockArray = mix_columns(blockArray)
      blockArray = add_round_key(blockArray, @roundKeys[round])
    }
    # special round without mix_columns
    blockArray = substitution(blockArray,S)
    blockArray = shift_rows(blockArray,0)
    blockArray = add_round_key(blockArray, @roundKeys[@rounds])
    return(blockArray)
  end
  
  
  def encrypt_block(block)
    raise "block must be #{@blockSize} bytes long" if (block.length() != @blockSize)
    blockArray = [[], [], [], []]
    0.upto(@blockSize - 1) { |pos|
      blockArray[pos % 4][pos / 4] = block[pos]
    }
    encryptedBlock = encrypt_byte_array(blockArray)
    encrypted = ""
    0.upto(@blockSize - 1) { |pos|
      encrypted << encryptedBlock[pos % 4][pos / 4]
    }
    return(encrypted)
  end
  
  
  def decrypt_byte_array(blockArray)
    # first special round without inverse_mix_columns
    # add_round_key is an involution - applying it a second time returns the original result
    blockArray = add_round_key(blockArray, @roundKeys[@rounds]) 
    blockArray = substitution(blockArray,Si)   # using inverse S-box
    blockArray = shift_rows(blockArray,1)
    (@rounds-1).downto(1) { |round|
      blockArray = add_round_key(blockArray, @roundKeys[round])
      blockArray = inverse_mix_columns(blockArray)
      blockArray = substitution(blockArray, Si) 
      blockArray = shift_rows(blockArray, 1)
    }
    blockArray = add_round_key(blockArray, @roundKeys[0])
    return(blockArray)
  end
  
  
  def decrypt_block(block)
    raise "block must be #{@blockSize} bytes long" if (block.length() != @blockSize)
    blockArray = [[], [], [], []]
    0.upto(@blockSize - 1) { |pos|
      blockArray[pos % 4][pos / 4] = block[pos]
    }
    decryptedBlock = decrypt_byte_array(blockArray)
    decrypted = ""
    0.upto(@blockSize - 1) { |pos|
      decrypted << decryptedBlock[pos % 4][pos / 4]
    }
    return(decrypted)
  end
  
  
end
end  #--}}}

# stringxor.rb  Richard Kernahan <kernighan_rich@rubyforge.org>
module Crypt  #--{{{
module StringXor
  
  
  def ^(aString)
    a = self.unpack('C'*(self.length))
    b = aString.unpack('C'*(aString.length))
    if (b.length < a.length)
      (a.length - b.length).times { b << 0 }
    end
    xor = ""
    0.upto(a.length-1) { |pos|
      x = a[pos] ^ b[pos]
      xor << x.chr()
    }
    return(xor)
  end
  
  
end
end

class String
  include Crypt::StringXor
end  #--}}}
