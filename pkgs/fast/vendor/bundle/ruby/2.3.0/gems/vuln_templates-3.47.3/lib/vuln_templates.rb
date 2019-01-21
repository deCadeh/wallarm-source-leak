require_relative './vuln_templates/version'
require_relative './vuln_templates/data_loader'
require_relative './vuln_templates/filler'
require_relative './vuln_templates/helpers'
require_relative './vuln_templates/to_utf8'
require_relative './vuln_templates/force_escape_html'
require_relative './vuln_templates/api'

module VulnTemplates
  UnknownTemplate = Class.new(RuntimeError)
  UnknownView     = Class.new(RuntimeError)
  UnknownLanguage = Class.new(RuntimeError)
  MissingParam    = Class.new(RuntimeError)
  UnexpectedParam = Class.new(RuntimeError)
  InvalidParam    = Class.new(RuntimeError)
  InvalidFile     = Class.new(RuntimeError)

  @@opt = {
    :lang                  => :en,
    :exploit_example_limit => 4000,
    :additional_limit      => 15000,
    :fill_filter_field     => true,
    :fill_template_params  => true
  }

  module_function

  def force_param_add_methods(str)
    def str.join(d)
      @each_called = true
      return 'N/A' + d + 'N/A'
    end

    def str.each
      @each_called = true
      yield 'N/A'
    end

    def str.each_called
      @each_called
    end

    def str.force_escape_html
      return self
    end
  end

  def force_param
    str = 'N/A'
    force_param_add_methods(str)
    str
  end

  def opt
    @@opt
  end

  def fill(template, params, opt={})
    values   = {}
    opt      = @@opt.merge(opt)
    template = handle_template template

    # Use :en language by default
    DataLoader.tmpls.load_template(values, template, :en)
    DataLoader.tmpls.load_template(values, template, opt[:lang], false)

    footers = params[:footers]
    params.delete(:footers)

    params.each do |param, value|
      unless (Params::PREMIT +
              Params::PARAMS +
              DataLoader.tmpls.required_params[template].keys).include? param
        raise UnexpectedParam, param
      end
    end

    # Do not force html escape custom template
    if template == 0
      params.each do |param, value|
        if value.is_a?(String)
          def value.skip_escape_html
          end
        end
      end
    end

    result = DataLoader.tmpls.fill(values, params, opt)

    # Force template params
    force(result, params)

    # Fill footers
    if footers
      fill_footer(result, footers, opt, opt[:lang])
    end

    # Format params values
    format(result, opt)

    if opt[:fill_filter_field]
      fill_filter_field(result)
    end

    if opt[:fill_template_params]
      fill_template_params(result, template, params, footers)
    end

    return result.force_utf8
  end

  def check?(template, params, opt={})
    fill(template, params, opt)
    return {result: true}
  rescue UnexpectedParam => e
    return {result: false, errors: {e.message => :unexpected}}
  rescue UnknownLanguage => e
    return {result: false, errors: {e.message => :invalid}}
  rescue MissingParam    => e
    return {result: false, errors: {e.message => :missing}}
  rescue UnknownTemplate => e
    return {result: false, errors: {:template => :not_found}}
  rescue UnknownView     => e
    return {result: false, errors: {:view     => :not_found}}
  rescue InvalidParam    => e
    return {result: false, errors: {e.message => :invalid}}
  end

  def handle_template template
    case template
    # Support old names
    when String
      if template =~ /\A\d+\z/
        template = template.to_i
      else
        template = template.gsub(/\A\//,'')
        if template.gsub(/\//,'').size == 0
          raise UnknownTemplate, template
        end

        id = DataLoader.tmpls.reverse_index[template.gsub('/', '_')]
        if id.nil?
          raise UnknownTemplate, template
        end

        template = id
      end
    when Fixnum
      # Nothing to do
    else
      raise InvalidParam, :template
    end
    template
  end

  def handle_view view
    case view
    when String
      if view =~ /\A\d+\z/
        view = view.to_i
      else
        id = DataLoader.views.reverse_index[view]
        if id.nil?
          raise UnknownView, view
        end
        view = id
      end
    when Fixnum
      # Nothing to do
    else
      raise InvalidParam, :view
    end
    view
  end

  private

  module_function

  def fill_footer(result, footers, opt, lang)
    unless footers.class==Hash
      raise InvalidParam, :footers
    end
    footers.each do |k, data|
      unless Params::FOOTER.include? k
        raise UnexpectedParam, 'footers:' + k.to_s
      end
      [data].flatten.each do |v|
        splitter   = v[:splitter]
        splitter ||= '<br>'
        if result[k]=='N/A'
          result[k]  = ''
        else
          result[k] += splitter
        end
        (v.keys-[:view, :params, :splitter]).each do |param|
          raise UnexpectedParam, "footers:#{k}:#{param}"
        end

        view       = handle_view v[:view]
        str        = DataLoader.views.load_view(view, lang)

        v[:params] && v[:params].each do |param, _|
          unless DataLoader.views.required_params[view].keys.include? param
            raise UnexpectedParam, "footers:#{k}:#{v[:view]}:params:#{param}"
          end
        end

        begin
          result[k] += DataLoader.views.fill(str, v[:params], opt)
        rescue InvalidParam => e
          raise InvalidParam, "footers:#{k}:#{v[:view]}:params"
        rescue MissingParam => e
          raise MissingParam, "footers:#{k}:#{v[:view]}:params:" + e.message
        end
      end
    end
  end

  def deep_copy(obj)
    Marshal.load(Marshal.dump(obj))
  end

  def fill_template_params(hash, template, params, footers)
    hash[:template]        = template.to_s
    hash[:template_params] = params
    hash[:template_params][:footers] = footers if footers
    hash
  end

  def fill_filter_field(hash)
    filter = {}
    Params::FILTER.each do |k|
      filter[k] = hash[k] if hash[k]
    end
    hash[:filter] = filter if filter.size>0
  end

  def force(hash, params)
    params.each do |k,v|
      if Params::EXCLUDE.include? k
        raise UnexpectedParam, k
      end
      hash[k] = v.to_s if hash[k]
    end
  end

  def format(hash, opt)
    hash.merge! ({
      :threat => hash[:threat].to_i
    })
    hash[:exploit_example] = truncate(
      hash[:exploit_example], opt[:exploit_example_limit]
    )
    hash[:additional] = truncate(
      hash[:additional], opt[:additional_limit]
    )
  end

  def truncate(str, limit)
    data   = str
    result = str
    if data && data.bytesize > limit
      str    = "\n\n...\n\n#{data.bytesize} bytes"
      result = data[0...limit-str.size] + str
    end
    return result
  end
end

