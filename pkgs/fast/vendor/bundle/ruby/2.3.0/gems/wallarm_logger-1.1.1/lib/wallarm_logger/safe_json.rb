require 'json'

module JSON
  def self.safe_dump(obj)
    fast_generate(as_safe_json(obj))
  end

  def self.as_safe_json(obj)
    case obj
    when Array
      obj.map{ |e| JSON.as_safe_json(e) }
    when Hash
      Hash[obj.map{ |k,v| [JSON.as_safe_json(k), JSON.as_safe_json(v)] }]
    when Float::INFINITY
      "<Infinity>"
    when -Float::INFINITY
      "<-Infinity>"
    when Numeric, TrueClass, FalseClass, NilClass
      obj
    else
      str = obj.to_s[0..5000]
      unless str.encoding == Encoding::UTF_8 and str.valid_encoding?
        str.encode!('utf-8','iso8859-1')
      end
      str
    end
  end
end
