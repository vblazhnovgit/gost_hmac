module GostHmac
  class KdfTree256
    def self.generateKey(key_in, label, seed, num_R, out_len)
=begin
	if (kin_len != 32) {
		rc = ER_BADPARAMS;
		goto done;
	}
	if (R > 4) {
		rc = ER_BADPARAMS;
		goto done;
	}
=end
      n = out_len / 32
      if out_len % 32 > 0 then
        n += 1
      end
      buf = ''
      data = 0.chr * num_R + label + 0.chr + seed + (out_len / 32).chr + (out_len % 32).chr
      (0...n).each do |i|
        data[num_R-1] = (i+1).chr
        hmac = Hmac.new(key_in, 32).update(data).final
        buf += hmac
      end
      return buf[0...out_len]
    end
  end
end
