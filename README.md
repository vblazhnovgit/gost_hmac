# GostHmac

HMAC algorithm for GOST R 34.11-2012 digest 

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'gost_hmac'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install gost_hmac

## Usage

Depends on crypto_gost3411 gem.

```ruby
require 'gost_hmac'
include GostHmac

# TC 26 HMAC test
HmacKey = [
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
].pack('C*').freeze    

HmacData = [
  0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21,
  0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
].pack('C*').freeze

Hmac_32 = [
  0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 
  0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
  0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 
  0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
].pack('C*').freeze

Hmac_64 = [
  0xa5, 0x9b, 0xab, 0x22, 0xec, 0xae, 0x19, 0xc6, 
  0x5f, 0xbd, 0xe6, 0xe5, 0xf4, 0xe9, 0xf5, 0xd8,
  0x54, 0x9d, 0x31, 0xf0, 0x37, 0xf9, 0xdf, 0x9b, 
  0x90, 0x55, 0x00, 0xe1, 0x71, 0x92, 0x3a, 0x77,
  0x3d, 0x5f, 0x15, 0x30, 0xf2, 0xed, 0x7e, 0x96, 
  0x4c, 0xb2, 0xee, 0xdc, 0x29, 0xe9, 0xad, 0x2f,
  0x3a, 0xfe, 0x93, 0xb2, 0x81, 0x4f, 0x79, 0xf5, 
  0x00, 0x0f, 0xfc, 0x03, 0x66, 0xc2, 0x51, 0xe6
].pack('C*').freeze

hmac = Hmac.new(HmacKey, 32).update(HmacData).final
puts "hmac == Hmac_32: #{hmac == Hmac_32}"

hmac = Hmac.new(HmacKey, 64).update(HmacData).final
puts "hmac == Hmac_64: #{hmac == Hmac_64}"
```

Additionally implemented Pkcs5 static class for password-based key generation:

```ruby
require 'gost_hmac'
include GostHmac

# Password-based GOST PKCS#5 key generation with iter_count=2000 takes a few seconds.
# To make it more fast use C implementation, please.

Password7 = "01234567" # (8 octets)
Password12 = "Пароль для PFX".force_encoding('BINARY')  # Cyrillic UTF-8 password

Salt7 = [
  0x8D, 0x47, 0x81, 0x05, 0x26, 0x6D, 0xF5, 0x94, 
  0x09, 0x6E, 0x26, 0xC6, 0x0D, 0x2B, 0x93, 0x89,
  0xFC, 0x41, 0xCB, 0x22, 0x5D, 0xE6, 0x68, 0x7D, 
  0x6F, 0xE4, 0xF8, 0x72, 0xFF, 0x60, 0x08, 0xCA
].pack('C*').freeze    
Salt12 = [
  0xA9, 0xCF, 0x20, 0x90, 0x04, 0x8F, 0xAB, 0xCD, 
  0xF2, 0x12, 0x78, 0xAB, 0xCF, 0x57, 0x54, 0x4E,
  0x7D, 0xC5, 0xE2, 0x61, 0x4F, 0x77, 0x9B, 0x07, 
  0x25, 0xD7, 0x14, 0x15, 0xD8, 0x6E, 0x7F, 0x7E
].pack('C*').freeze

Ic7 = 2000

KeyLen7 = 32
KeyLen12 = 96

Et7 = [
  0xe5, 0xc5, 0x8a, 0x6e, 0xf8, 0x81, 0xcd, 0x27,
  0x0e, 0x63, 0x69, 0x43, 0xc4, 0xf3, 0x31, 0x99,
  0x9f, 0x33, 0x46, 0x40, 0xf0, 0x55, 0x24, 0xb7,
  0x40, 0x30, 0xbf, 0x50, 0xeb, 0x4f, 0xec, 0x6d
].pack('C*').freeze
Et12 = [
  0xca, 0xdb, 0xfb, 0xf3, 0xbc, 0xea, 0xa9, 0xb7,
  0x9f, 0x65, 0x15, 0x08, 0xfa, 0xc5, 0xab, 0xbe,
  0xb4, 0xa1, 0x3d, 0x0b, 0xd0, 0xe1, 0x87, 0x6b,
  0xd3, 0xc3, 0xef, 0xb2, 0x11, 0x21, 0x28, 0xa5
].pack('C*').freeze

key7 = Pkcs5::generateKey(Password7, Salt7, Ic7, KeyLen7)
puts "key7 == Et7: #{key7 == Et7}"

# TC 26 PKCS#12 HMAC key generation example
# First generate 96 bytes
key96 = Pkcs5::generateKey(Password12, Salt12, Ic7, KeyLen12) 
# Then get last 32 bytes
key12 = key96[-32..-1]
puts "key12 == Et12: #{key12 == Et12}"
```

Additionally implemented KdfTree256 static class for key tree generation:

```ruby
require 'gost_hmac'
include GostHmac

Key_in = [
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
].pack('C*').freeze

Seed = [
	0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78
].pack('C*').freeze

Label = [
	0x26, 0xBD, 0xB8, 0x78
].pack('C*').freeze

# R=1, L=32 
Kdf_32 = [
	0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 
	0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
	0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 
	0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
].pack('C*').freeze

# R = 1, L = 64
Kdf_64 = [
	0x22, 0xb6, 0x83, 0x78, 0x45, 0xc6, 0xbe, 0xf6, 
	0x5e, 0xa7, 0x16, 0x72, 0xb2, 0x65, 0x83, 0x10,
	0x86, 0xd3, 0xc7, 0x6a, 0xeb, 0xe6, 0xda, 0xe9, 
	0x1c, 0xad, 0x51, 0xd8, 0x3f, 0x79, 0xd1, 0x6b,
	0x07, 0x4c, 0x93, 0x30, 0x59, 0x9d, 0x7f, 0x8d, 
	0x71, 0x2f, 0xca, 0x54, 0x39, 0x2f, 0x4d, 0xdd,
	0xe9, 0x37, 0x51, 0x20, 0x6b, 0x35, 0x84, 0xc8, 
	0xf4, 0x3f, 0x9e, 0x6d, 0xc5, 0x15, 0x31, 0xf9
].pack('C*').freeze

# R = 2, L = 64
Kdf_2_64 = [
	0xb7, 0x4e, 0xea, 0x99, 0x7c, 0x9d, 0xa9, 0x16,
	0x0c, 0xe1, 0xa3, 0x3d, 0xdd, 0xb2, 0xd7, 0x52,
	0x89, 0xfe, 0xe7, 0xd4, 0x79, 0x67, 0x06, 0x87,
	0x85, 0x1d, 0x9c, 0xf9, 0xca, 0x9f, 0xed, 0x32,
	0xdd, 0x5b, 0x85, 0x2e, 0x3f, 0x82, 0x6d, 0xb5,
	0x0e, 0x7c, 0xbe, 0xb0, 0x48, 0xd4, 0x9e, 0x19,
	0xdc, 0xa7, 0x2d, 0x4f, 0x8b, 0x99, 0x49, 0x11,
	0x29, 0xc7, 0x5c, 0xd5, 0x1a, 0x08, 0x62, 0x91
].pack('C*').freeze

puts 'Testing GOST R 34.11-2012 KDF TREE'

puts 'R = 1, L = 32'
kdf = KdfTree256.generateKey(Key_in, Label, Seed, 1, 32)
puts "kdf == Kdf_32: #{kdf == Kdf_32}"

puts 'R = 1, L = 64'
kdf = KdfTree256.generateKey(Key_in, Label, Seed, 1, 64)
puts "kdf == Kdf_64: #{kdf == Kdf_64}"

puts 'R = 2, L = 64'
kdf = KdfTree256.generateKey(Key_in, Label, Seed, 2, 64)
puts "kdf == Kdf_2_64: #{kdf == Kdf_2_64}"
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/vblazhnovgit/gost_hmac.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
