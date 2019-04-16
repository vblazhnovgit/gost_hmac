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
        itmp = [(count>>24)&0xff, (count>>16)&0xff, (count>>8)&0xff, count&0xff].pack('C*')
        buf = hmac_ctx.reset.update(salt).update(itmp).final
        puts '-'*40
        printf("count = %d\n", count)
        puts '-'*40
        puts 'buf:'
        printBytes(buf)
        keyBuf[resPos...resPos+outLen] = buf[0...outLen]
        puts 'keyBuf:'
        printBytes(buf)        
        (1...iter_count).each do |i|
          buf = hmac_ctx.reset.update(buf).final
          (0...outLen).each do |j|
             keyBuf[resPos+j] = (keyBuf[resPos+j].ord ^ buf[j].ord).chr
          end        
        end
        puts 'Iterated keyBuf:'
        printBytes(keyBuf)                
        keyLen -= outLen
        count += 1
        resPos += outLen
      end
      puts '='*40
      key = keyBuf[0...keyLen].dup
      puts 'key:'
      printBytes(key)                
      puts '='*40
      key
    end
    
    def self.printBytes(bytes, line_size = 16)
      bytes.unpack('H*')[0].scan(/.{1,#{line_size}}/).each{|s| puts(s)}
    end

  end
end
