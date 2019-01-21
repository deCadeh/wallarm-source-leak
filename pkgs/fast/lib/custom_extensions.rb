require 'fast_dsl'

module CustomExtensions
  class CustomExtension < ScannerExtensions::BaseExtension
    def applicable?(object)
      return false if CustomExtensions.custom_detects.empty?
      CustomExtensions.custom_detects.values.any? { |detect| detect.applicable?(object) }
    end

    def initialize
      @type                = :detect
      @general_object_type = :param
      @extension_type      = :vuln
      @detect_type         = :custom
      @defaults            = {}
    end

    def run(object, params)
      CustomExtensions.custom_detects.each do |name, detect|
        next unless detect.applicable?(object)

        ctx = detect.run(object)

        if !ctx.vuln? && !ctx.oob_callbacks.empty?
          object.oob_callbacks << Proc.new do
            ctx.oob_callbacks.each do |callback|
              callback.call

              break if ctx.vuln?
            end

            ctx.vuln? ? fill_vuln(object, ctx, name: name) : nil
          end
        end

        next unless ctx.vuln?

        fill_vuln(object, ctx, name: name)
      end
    end

    private

    def fill_vuln(object, ctx, params = {})
      vuln = ctx.vulns.first

      curl_hash = { value: vuln.insertion_point_value }
      curl_hash[:resp] = vuln.exploit_stamp if vuln.type == :sync
      curl = object.curl_helper(curl_hash)

      vuln_params = ctx.meta_info.to_h

      if vuln.type == :async
        vuln_params[:footers] = {
          additional: {
            view: 'oob_dns',
            splitter: "\n",
            params: { hosts: vuln.oob_triggered_ip }
          }
        }
      end

      defaults = {
        title:       "Custom #{vuln_params[:type].to_s.upcase} issue",
        description: 'N/A',
        additional:  'N/A'
      }

      # default template
      if vuln_params.values_at(*defaults.keys).compact.empty?
        object.vuln(
          template: 'fast',
          scid:     params[:name],
          args: {
            trigger:         vuln.trigger_name,
            payload:         vuln.payload,
            marker:          vuln.marker,
            target:          :server,
            exploit_example: curl
          }.merge(vuln_params)
        )
      # custom template
      else
        defaults.each do |key, val|
          vuln_params["custom_#{key}".to_sym] = vuln_params[key] || val
        end

        %i[title description addititonal].each { |key| vuln_params.delete(key) }

        object.vuln(
          template: 'custom',
          scid:     params[:name],
          args: { exploit_example: curl, target: :server }.merge(vuln_params)
        )
      end

      object
    end
  end

  @custom_detects = {}

  module_function

  def custom_extension
    @custom_extension ||= CustomExtension.new
  end

  def custom_detects
    @custom_detects
  end

  def load(path)
    @custom_detects = {}

    Dir["#{path}/**.yaml"].each do |file|
      ext  = load_extension(file)
      name = file.split('/').last.split('.').first
      @custom_detects[name] = ext if ext
    end

    App.logger.info("Loaded #{@custom_detects.size} custom extensions")
  end

  def load_extension(file)
    data = YAML.safe_load(IO::binread(file))
    FastDsl::Detect.new(data)
  rescue => ex
    App.logger.error("Invalid custom extension '#{file.split('/').last}': #{ex}")
    return nil
  end
end
