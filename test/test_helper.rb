$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "gost_hmac"

require "minitest/autorun"
require "minitest/reporters"
Minitest::Reporters.use!
