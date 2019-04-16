module GostHmac
  class Pkcs5
    def self.generateKey(pswd_utf8, salt, iter_count, key_len)
      keyLen = key_len
      hmacLen = 64
      hmac_ctx = Hmac.new(pswd_utf8, hmacLen)
      count = 1
      resPos = 0
        if keyLen > hmacLen then
          keyBufLen = keyLen
        else
          keyBufLen = hmacLen
        end
      keyBuf = 0.chr * keyBufLen
      while keyLen > 0 do
        if keyLen > hmacLen then
          outLen = hmacLen
        else
          outLen = keyLen
        end
        itmp = [((count>>24)&0xff).chr,
          ((count>>16)&0xff).chr,
          ((count>>8)&0xff).chr
          (count&0xff).chr]
        buf = hmac_ctx.reset.update(salt).update(itmp).final
        
        (1...iter_count).each do |i|
          buf = hmac_ctx.reset.update(buf).final
          (0...outLen).each do |j|
             keyBuf[resPos+j] = (keyBuf[resPos+j].ord ^ buf[j].ord).chr
          end        
        end
        
        keyLen -= outLen
        count += 1
        resPos += outLen
      end
      key = keyBuf[0...keyLen].dup
    end
  end
end
