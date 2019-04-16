module GostHmac

require 'crypto_gost3411'
include CryptoGost3411

  class Hmac
  
    def initialize(key, hmac_size)
      @dgst_size = hmac_size
      key_len = key.length
      if key_len <= 64 then
        standard_key = self.class.zeroBytes(64)
        standard_key[0...key_len] = key
      else
        standard_key = Gost3411.new(64).update(key).final
      end
      puts 'standard_key:'
      self.class.printBytes(standard_key)
      ipad = standard_key.dup
      @opad = standard_key.dup
      (0...64).each do |i|
        ipad[i] = (ipad[i].ord ^ 0x36).chr
        @opad[i] = (@opad[i].ord ^ 0x5c).chr
      end
      puts 'ipad:'
      self.class.printBytes(ipad)
      puts '@opad:'
      self.class.printBytes(@opad)
      @dgst_ctx = Gost3411.new(@dgst_size)
      @dgst_ctx.update(ipad)
    end
    
    def update(data)
      @dgst_ctx.update(data)
    end
    
    def final
      hmac_buf = @dgst_ctx.final
      puts 'hmac_buf:'
      self.class.printBytes(hmac_buf)
      
      hmac = Gost3411.new(@dgst_size).update(@opad).update(hmac_buf).final      
      puts 'hmac:'
      self.class.printBytes(hmac)
      hmac
    end
    
    protected
    
    def self.printBytes(bytes, line_size = 16)
      bytes.unpack('H*')[0].scan(/.{1,#{line_size}}/).each{|s| puts(s)}
    end

    def self.zeroBytes(n)
      ("\x00"*n).force_encoding('BINARY')
    end
        
  end
end
