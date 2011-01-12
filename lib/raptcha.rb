#! /usr/bin/env ruby

module Raptcha

  README = <<-__
    NAME
      raptcha.rb

    SYNOPSIS
      super low drain bamage, K.I.S.S., storage-less, session-less,
      plugin-less, dependency-less, zero admin, single-source-file secure
      captcha system for ruby and/or rails.

      bitchin.

    DESCRIPTION
      raptcha manages image generation via a streaming controller.  the result
      is that *no* disk storage is ever needed for captcha images.  it also
      manages authentication via openssl(aes-256) encoded hidden fields which
      are relayed through the form submission process, obviating the need for
      session/database interaction for captcha validation.  the library is
      useful outside of rails, even from the command line.

      what this means to you is that you can have a nice looking, and easy to
      customize, safe captcha solution in about 1 minute that requires zero
      maintenance moving forward.

      see a sample image here
        http://github.com/ahoward/raptcha/blob/master/images/raptcha.png

    INSTALL
      1) INSTALL Image Magick 
          ~> which convert

      2) COPY A SINGLE FILE INTO YOUR RAILS APP
          ~> cp raptcha.rb ./app/lib/

      3) GENERATE THE CONROLLER
          ruby lib/raptcha.rb generate controller

      4) ADD A ROUTE
          match 'raptcha(/:action)', :controller => 'raptcha'

      5) PUT A RAPTCHA IMAGE AND FORM INPUT IN YOUR VIEW
          <%= Raptcha.input %>

      6) REQUIRE VALID RAPTCHA INPUT IN A CONTROLLER ACTION
          class SessionsController < ApplicationController
            def create 
              unless Raptcha.valid?(params)
                # ...
              end
            end
          end

      7) TRY THE EXAMPLES LOCALLY AT
          http://0.0.0.0:3000/raptcha/form
          http://0.0.0.0:3000/raptcha/inline

    URIS
      http://github.com/ahoward/raptcha
      http://codforpeople.com


    COMMAND LINE USAGE
      * make an image by hand
        ~> ruby lib/raptcha.rb image foreground:pink raptcha.png && open raptcha.png

      * generate the controller
        ~> ruby lib/rapcha.rb generate controller

    DOC
      less lib/raptcha.rb
  __

  Version = '2.0.0' unless defined? Raptcha::Version
  def Raptcha.version() Version end

  require 'base64'
  require 'socket'
  require 'openssl'

  module Image
    class << Image
      def create(options = {})
        options = Raptcha.normalize(options)

        word = options[:word] || options[:w]
        encrypted = options[:encrypted] || options[:e]
        word ||= Encryptor.decrypt(encrypted) if encrypted
        word ||= Raptcha.word
        word = word.split(%r"").join(" ").strip.upcase

        Image.for(word)
      end

      def for(word)
        command = %W(
          convert
            -size '222x42'
            -strokewidth 1
            -gravity center
            -fill '#333'
            -family 'monoco'
            -pointsize 42
            -bordercolor white
            -border 10 
            -annotate "0x0" #{ word.inspect }
            -implode 0.2
            -strokewidth 10
            -draw 'line 5 25 295 25'
            -draw 'line 5 35 295 35'
            -wave '3x50'
            xc:white jpg:-
        )
        command = command.join(' ')
        IO.popen(command){|pipe| pipe.read}
      end

      def inline(options = {})
        Base64.encode64(create(options))
      end
    end
  end

  module Encoder
    def encode(string)
      return nil if string.nil?
      Base64.encode64(string.to_s).gsub(/[\s=]+/, "").gsub("+", "-").gsub("/", "_")
    end
    
    def decode(string)
      return nil if string.nil?
      case string.length.modulo(4)
      when 2
        string += '=='
      when 3
        string += '='
      end
      Base64.decode64(string.gsub("-", "+").gsub("_", "/"))
    end

    extend(Encoder)
  end

  module Encryptor
    def encrypt(plaintext, options = {})
      plaintext = plaintext.to_s
      key = options[:key] || options['key'] || Encryptor.key
      alg = options[:alg] || options['alg'] || Encryptor.alg
      salt = options[:salt] || options['salt'] || Encryptor.salt
      enc = OpenSSL::Cipher::Cipher.new(alg)
      enc.encrypt
      enc.pkcs5_keyivgen(key, salt)
      ciphertext =  enc.update(plaintext)
      ciphertext << enc.final
      Encoder.encode(ciphertext)
    end

    def decrypt(ciphertext, options = {})
      ciphertext = Encoder.decode(ciphertext.to_s)
      key = options[:key] || options['key'] || Encryptor.key
      alg = options[:alg] || options['alg'] || Encryptor.alg
      salt = options[:salt] || options['salt'] || Encryptor.salt
      dec = OpenSSL::Cipher::Cipher.new(alg)
      dec.decrypt
      dec.pkcs5_keyivgen(key, salt)
      plaintext =  dec.update(ciphertext)
      plaintext << dec.final
    end

    def cycle(plaintext, options = {})
      decrypt(encrypt(plaintext, options), options)
    end

    def key(*key)
      self.key = key.first.to_s unless key.empty?
      self.key = default_key unless defined?(@key)
      @key
    end

    def default_key
      Rails.application.config.secret_token
    end

    def key=(key)
      @key = key.to_s[0, 56]
    end

    def alg
      @alg ||= 'AES-256-CBC'
    end

    def salt
      @salt ||= nil
    end

    def salt=(salt)
      @salt = salt
    end

    extend(self)
  end

  class Error < ::StandardError; end
  class NoInput < Error; end
  class BadInput < Error; end
  class Expired < Error; end

  class << Raptcha
    def key
      @key ||= Rails::Application.config.secret_token
    end

    def route
      @route ||= '/raptcha'
    end

    def gravity
      @gravity ||= 'north'
    end

    def ttl
      @ttl ||= 30 * 60
    end

    def close_enough
      @close_enough ||= {
        '0OoQ' => '0',
        '1l'   => '1',
        '2zZ'  => '2',
        '5sS'  => '5',
        'kKxX' => 'x',
      }
    end

    def normalize(options)
      options.inject({}){|h, kv| h.update(kv.first.to_s.to_sym => kv.last) }
    end

    def valid?(params)
      begin
        validate!(params)
      rescue NoInput
        nil
      rescue BadInput, Expired
        false
      end
    end

    def validate!(params)
      params = Raptcha.normalize(params)

      if params.has_key?(:raptcha)
        raptcha = params[:raptcha]

        textarea = raptcha[:t]
        word = raptcha[:w]
        timebomb = raptcha[:b]

        raise NoInput unless(textarea and word and timebomb)

        word = Encryptor.decrypt(word)
        timebomb = Encryptor.decrypt(timebomb)

        begin
          timebomb = Integer(timebomb)
          timebomb = Time.at(timebomb).utc
          now = Time.now.utc
          raise Expired unless now < timebomb
        rescue
          raise Expired
        end

        raise BadInput unless fuzzy_match(word, textarea)

        textarea
      else
        validate!(:raptcha => params)
      end
    end

    def fuzzy(word)
      result = word.to_s.downcase
      close_enough.each do |charset, replace|
        result.gsub!(%r"[#{ charset }]", replace)
      end
      result.upcase.strip
    end

    def fuzzy_match(a, b)
      fuzzy(a) == fuzzy(b)
    end

    def input(options = {})
      options = Raptcha.normalize(options)

      options[:route] ||= Raptcha.route
      options[:word] ||= Raptcha.word
      options[:timebomb] ||= Raptcha.timebomb
      options[:gravity] ||= Raptcha.gravity

      encrypted_word = Encryptor.encrypt(options[:word])
      encrypted_timebomb = Encryptor.encrypt(options[:timebomb])

      west = north = east = south = nil

      case gravity.to_s
        when /w(est)?/
          west = Raptcha.img(options)
        when /n(orth)?/
          north = Raptcha.img(options) + '<br>'
        when /e(ast)?/
          east = Raptcha.img(options)
        when /s(outh)?/
          south = '<br>' + Raptcha.img(options)
      end

      html =
        <<-html
          <div class="raptcha">
            #{ north } #{ west }
            <input type="textarea" name="raptcha[t]" value="" class="raptcha-input"/>
            <input type="hidden" name="raptcha[w]" value="#{ encrypted_word }" class="raptcha-word"/>
            <input type="hidden" name="raptcha[b]" value="#{ encrypted_timebomb }" class="raptcha-timebomb"/>
            #{ east } #{ south }
          </div>
        html

      singleton_class =
        class << html
          self
        end
      word = options[:word]
      singleton_class.send(:define_method, :word){ word }

      html
    end
    alias_method "tag", "input"

    def img(options = {})
      options = Raptcha.normalize(options)
      return(inline(options)) if options[:inline]
      route = options[:route] || Raptcha.route
      word = options[:word] || Raptcha.word
      encrypted_word = Encryptor.encrypt(word)
      %[
        <img src="#{ route }?e=#{ encrypted_word }" alt="raptcha.png" class="raptcha-image"/>
      ]
    end

    def inline(options = {})
      options = Raptcha.normalize(options)
      %[
        <img src="data:image/png;base64,#{ Image.inline(options)  }" alt="raptcha.png" class="raptcha-image"/>
      ]
    end

    def timebomb
      Time.now.utc.to_i + Raptcha.ttl
    end

    def word(size = 6)
      word = ''
      size.times{ word << alphabet[rand(alphabet.size - 1)]}
      word
    end

    def alphabet
      @alphabet ||= ('A' .. 'Z').to_a
    end

    def image(*args, &block)
      Raptcha::Image.create(*args, &block)
    end

    def render(controller, params)
      controller.instance_eval do
        send_data(Raptcha.image(params), :type => 'image/png', :disposition => 'inline', :filename => 'raptcha.png')
      end
    end
  end
end









if $0 == __FILE__

# the command line code
#
  module Raptcha
    class CLI
      def CLI.run
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

      def rails_root?(&block)
        boolean = test(?d, 'app') && test(?d, 'app/controllers')
        return boolean unless block
        boolean ? block.call() : abort('run this in a RAILS_ROOT')
      end

      def generate_controller
        src = DATA.read.strip

        rails_root? do
          path = File.join 'app', 'controllers', 'raptcha_controller.rb'
          if test(?e, path)
            puts "exists #{ path }"
            exit 1
          end
          open(path, 'w'){|fd| fd.puts(src)}
          puts "#{ path }"
        end
      end

      def generate_lib
        src = IO.read(__FILE__).strip

        rails_root? do
          path = File.join('lib', 'raptcha.rb')
          if test(?e, path)
            puts "exists #{ path }"
            exit 1
          end
          open(path, 'w'){|fd| fd.puts(src)}
          puts "#{ path }"
        end
      end
    end
  end

  Raptcha::CLI.run
end

__END__

class RaptchaController < ApplicationController
# this is the image responder - it is the *only* action you need here
# 
# you may need a to route /raptcha to this action in config/routes.rb
# 
# match 'raptcha(/:action)', :controller => 'raptcha'
#
  def index
    Raptcha.render(controller=self, params)
  end

# sample on how to use - you may delete this action
#
  def form
    render :inline => <<-html
      <html>
        <body>
          <hr>
          <em>valid</em>:#{ Raptcha.valid?(params) ? :true : :false }
          <hr>
          <%= form_tag do %>
            #{ Raptcha.input }
            <hr>
            <input type=submit name=submit value=submit />
            <hr>
            <a href="#{ request.fullpath }">new</a>
          <% end %>
        </body>
      </html>
    html
  end

# sample inline image (IE incompatible) - you may delete this action
#
  def inline
    render :inline => <<-html
      <html>
        <body>
          <hr>
          <em>valid</em>:#{ Raptcha.valid?(params) ? :true : :false }
          <hr>
          <%= form_tag do %>
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

load 'lib/raptcha.rb' if Rails.env.development?
