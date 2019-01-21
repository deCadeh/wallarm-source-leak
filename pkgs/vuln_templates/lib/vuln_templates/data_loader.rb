require_relative './path.rb'
require 'yaml'

module VulnTemplates
  private

  class DataLoaderClass
    attr_reader :templates, :index, :reverse_index, :required_params

    def initialize(include_files, exclude_files=nil)
      @index        = {}
      current_file  = nil
      templates     = {}
      reverse_index = {}
      file(include_files, exclude_files).each do |f|
        current_file = f
        data = YAML.load(File.read(f))
        lang, name = f.split('/')[-2..-1]
        id,   name = name.split('_', 2)
        id   = id.to_i
        name = name.chomp('.yaml')
        templates[lang.to_sym]   ||= {}
        templates[lang.to_sym][id] = data
        @index[id] = name
        if lang.to_sym==:en
          # Select index with lowest id
          if reverse_index[name].nil? || reverse_index[name] < id
            reverse_index[name] = id
          end
        end
      end
      @templates       = templates
      @reverse_index   = reverse_index
    rescue Psych::SyntaxError
      raise InvalidFile, current_file
    end

    def list_id
      @index.keys
    end

    def list_params_by_id id
      params = {}
      while true
        begin
          try_fill id, params
          break
        rescue MissingParam => e
          params[e.message.to_sym] = VulnTemplates.force_param
        end
      end
      res = {}
      params.keys.each do |key|
        res[key] = params[key].each_called ? :array : :string
      end
      res
    end

    def list_params
      @required_params = {}
      @templates[:en].keys.each do |id|
        @required_params[id] = list_params_by_id(id)
      end
    end

    private

    def file(include_files, exclude_files)
      if exclude_files
        exclude_files = Dir[PATH + exclude_files].to_a
      else
        exclude_files = []
      end
      result = []
      Dir[PATH + include_files].each do |f|
        unless exclude_files.include? f
          result << f
        end
      end
      result
    end
  end

  class TmplsLoader < DataLoaderClass
    def load_template(values, template_id, lang, raise_on_fail = true)
      base = @templates[lang]
      if base.nil?
        raise UnknownLanguage, lang if raise_on_fail
        return
      end

      vuln = base[template_id]
      if vuln.nil?
        raise UnknownTemplate, template_id if raise_on_fail
        return
      end

      values.merge! vuln
    end

    def fill(values, params, opt)
      Filler.fill(values, params, opt)
    end

    def try_fill id, params
      values = load_template({}, id, :en)
      fill(values, params, {})
    end
  end

  class ViewsLoader < DataLoaderClass
    def load_view(view_id, lang)
      if templates[lang]
        str = @templates[lang][view_id]
      end
      str ||= @templates[:en][view_id]
    end

    def fill(str, params, opt)
      Filler.fill_view(str, params, opt)
    end

    def try_fill id, params
      str = load_view(id, :en)
      fill(str, params, {})
    end
  end

  module DataLoader
    @@tmpls = nil
    @@views = nil

    module_function

    def tmpls
      self.load
      @@tmpls
    end

    def views
      self.load
      @@views
    end

    def load
      @@tmpls ||= TmplsLoader.new  '/**/*.yaml', '/views/**/*.yaml'
      @@views ||= ViewsLoader.new  '/views/**/*.yaml'

      @@tmpls.required_params || @@tmpls.list_params
      @@views.required_params || @@views.list_params
    end

    def force_load
      @@tmpls = TmplsLoader.new  '/**/*.yaml', '/views/**/*.yaml'
      @@views = ViewsLoader.new  '/views/**/*.yaml'
    end
  end
end

