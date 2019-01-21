require 'erb'

class String
  def force_escape_html
    ERB::Util.h self
  end
end

class Array
  def force_escape_html
    self.map do |e|
      if (e.respond_to?(:force_escape_html))
        e.force_escape_html
      else
        e
      end
    end
  end
end

class Hash
  def force_escape_html
    Hash[
      self.collect do |k, v|
        if (v.respond_to?(:force_escape_html))
          [ k, v.force_escape_html ]
        else
          [ k, v ]
        end
      end
    ]
  end
end

