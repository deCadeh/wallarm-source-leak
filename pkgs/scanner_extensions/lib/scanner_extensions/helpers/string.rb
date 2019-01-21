class String
  def self.get_rand(len = 32)
    s = ''
    len.times do
      case rand(3)
      when 0
        s += ('a'.ord + rand(24)).chr
      when 1
        s += ('A'.ord + rand(24)).chr
      when 2
        s += ('0'.ord + rand(10)).chr
      end
    end
    s
  end
end

class String
  def margin
    arr = split("\n")
    arr.map! { |x| x.sub!(/\s*\|/, '') }
    str = arr.join("\n")
    replace(str)
  end

  def normalize_enconding
    h = { invalid: :replace, undef: :replace, replace: ' ' }
    encode('UTF-8', h).encode('UTF-16', h).encode('UTF-8').tr("\0", ' ')
  end
end
