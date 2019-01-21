class String
  def force_utf8
    h = { :invalid=>:replace, :undef => :replace, :replace=>'?' }
    self.encode('UTF-8', h)
  end
end

class Array
  def force_utf8
    self.map do |e|
      if (e.respond_to?(:force_utf8))
        e.force_utf8
      else
        e
      end
    end
  end
end

class Hash
  def force_utf8
    Hash[
      self.collect do |k, v|
        if (v.respond_to?(:force_utf8))
          [ k, v.force_utf8 ]
        else
          [ k, v ]
        end
      end
    ]
  end
end

