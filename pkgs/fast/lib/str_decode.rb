class String
  def str_decode
    self.encode('iso8859-1', 'utf-8').force_encoding('utf-8')
  end
end

class Array
  def str_decode
    self.map do |e|
      if (e.respond_to?(:str_decode))
        e.str_decode
      else
        e
      end
    end
  end
end

class Hash
  def str_decode
    Hash[
      self.collect do |k, v|
        if (v.respond_to?(:str_decode))
          v = v.str_decode
        end
        if (k.respond_to?(:str_decode))
          k = k.str_decode
        end
        [ k, v ]
      end
    ]
  end
end
