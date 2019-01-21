require 'liquid'

module RegexpReplaceFilter
  def regexp_replace(input, regexp, replace='')
    Thread.current[:liquid_matched] = false
    r = Regexp.new(regexp)
    if r =~ input
      Thread.current[:liquid_matched] = true
      input.gsub(r, replace)
    else
      input
    end
  end
end

Liquid::Template.register_filter(RegexpReplaceFilter)
