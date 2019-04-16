module GostHmac
  class Pkcs5
    def self.generateKey(pswd_utf8, salt, iter_count, key_len)
      keyLen = key_len
#      puts "key_len = #{key_len}"
      hmacLen = 64
      hmac_ctx = Hmac.new(pswd_utf8, hmacLen)
      count = 1
      resPos = 0
      if keyLen > hmacLen then
        keyBufLen = keyLen
      else
        keyBufLen = hmacLen
      end
#      puts "keyBufLen = #{keyBufLen}"  
      keyBuf = 0.chr * keyBufLen
#      puts '='*40
      while keyLen > 0 do 
=begin      
        printf("count = %d\n", count)
        puts '-'*40
=end        
        if keyLen > hmacLen then
          outLen = hmacLen
        else
          outLen = keyLen
        end
#        puts "outLen = #{outLen}"
        itmp = [(count>>24)&0xff, (count>>16)&0xff, (count>>8)&0xff, count&0xff].pack('C*')
        buf = hmac_ctx.reset.update(salt).update(itmp).final
=begin        
        puts 'buf:'
        puts '-'*40
        printBytes(buf)
=end        
        keyBuf[resPos...resPos+outLen] = buf[0...outLen]
=begin        
        puts 'keyBuf:'
        puts '-'*40
        printBytes(buf)        
        puts '-'*40
=end        
        (1...iter_count).each do |i|
          buf = hmac_ctx.reset.update(buf).final
          (0...outLen).each do |j|
             keyBuf[resPos+j] = (keyBuf[resPos+j].ord ^ buf[j].ord).chr
          end        
        end
=begin        
        puts 'Iterated keyBuf:'
        puts '-'*40
        printBytes(keyBuf)                
        puts '-'*40
=end        
        keyLen -= outLen
        count += 1
        resPos += outLen
      end
#      puts '='*40
      key = keyBuf[0...key_len].dup
=begin      
      puts 'key:'
      printBytes(key)                
      puts '='*40
=end      
      key
    end
    
    def self.printBytes(bytes, line_size = 16)
      bytes.unpack('H*')[0].scan(/.{1,#{line_size}}/).each{|s| puts(s)}
    end

  end
end
