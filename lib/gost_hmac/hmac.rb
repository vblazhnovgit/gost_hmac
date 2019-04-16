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
      @ipad = standard_key.dup
      @opad = standard_key.dup
      (0...64).each do |i|
        @ipad[i] = (@ipad[i].ord ^ 0x36).chr
        @opad[i] = (@opad[i].ord ^ 0x5c).chr
      end
      @dgst_ctx = Gost3411.new(@dgst_size)
      @dgst_ctx.update(@ipad)
    end
    
    def update(data)
      @dgst_ctx.update(data)
      return self
    end
    
    def final
      hmac_buf = @dgst_ctx.final
      hmac = Gost3411.new(@dgst_size).update(@opad).update(hmac_buf).final  
      hmac
    end
    
    def reset
      @dgst_ctx = Gost3411.new(@dgst_size)
      @dgst_ctx.update(@ipad)
      return self
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
