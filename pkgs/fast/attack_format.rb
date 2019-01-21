require 'base64'
require 'msgpack'

module AttackFormat
  module_function

  def dump(hash)
    hash = Marshal.load(Marshal.dump(hash))
    data = MessagePack.pack hash
    Base64.strict_encode64(data)
  end

  def load(data)
    res  = Base64.strict_decode64(data)
    MessagePack.unpack(res)
  end
end

