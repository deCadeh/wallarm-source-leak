require 'scanner_extensions'
require './lib/object_helpers'
require './lib/proton/proton_point'
require 'securerandom'
require 'erb'
require 'liquid_filters'
require 'uri'
require 'msgpack'

require_relative './fast_dsl_baseline'

module Wrappers
  # Extend Scanner with Proton support
  class ScannerObject < ScannerExtensions::Wrappers::Object
    attr_accessor :job
    attr_accessor :entry_method

    include FastDslBaseline

    ProtonError = Class.new(RuntimeError)

    def initialize(params = {})
      @params = params
      @params[:info] = {}
      process_rewrites
      parse(value: @params[:entry_value])
      super params
    end

    def wrap_proton_errors
      yield
    rescue
      raise ProtonError
    end

    def under_test?
      false
    end

    def init_test_run_policy(policy)
      allowed_payload_names = %w[
        all
        replace_all
        append
        prepend
        replace
        replace_random
        insert_random
      ]

      payloads = ObjectHelpers.get_policy_values_by_type(policy, 'payloads')
      payloads.map! { |p| p.delete("'").split }
      payload_names = payloads.map { |payload| payload[0] }

      # set default payload
      if (payload_names & allowed_payload_names).empty?
        payloads = [%w[replace_all 16]]
      end

      # paylads is fuzzer_policies for ScannerExtensions::Wrappers::Object
      @fuzzer_policies = payloads

      @include_conditions = ScannerExtensions::Helpers::FuzzerConditions.new(
        ObjectHelpers.get_policy_values_by_type(policy, 'criteria[extended]')
      )

      @exclude_conditions = ScannerExtensions::Helpers::FuzzerConditions.new(
        ObjectHelpers.get_policy_values_by_type(policy, 'criteria[excluded]'), true
      )

      @hardstop_conditions = ScannerExtensions::Helpers::FuzzerConditions.new(
        ObjectHelpers.get_policy_values_by_type(policy, 'criteria[hardstop]')
      )

      @has_conditions = true
    end

    def each_point_rewrite
      req = @params[:req]

      rewrites = req.tags['attack_rechecker_rewrite']
      return unless rewrites

      rewrites = MessagePack.unpack(rewrites)
      rewrites = [rewrites].flatten

      rewrites.each do |rewrite|
        rewrite.each do |point, rules|
          point = Proton::Point.new(point)
          next unless point
          [rules].flatten.each do |rule|
            template = Liquid::Template.parse(rule)
            next unless template
            yield point, template
          end
        end
      end
    end

    def process_uri_rewrites(uri)
      each_point_rewrite do |point, template|
        next unless point.to_a == [:uri]
        rendered = template.render('val' => uri)
        return rendered if Thread.current[:liquid_matched]
      end
      return nil
    rescue => e
      App.logger.error(e)
      App.logger.error 'Exception occured while processing rewrites, skip rewrites'
      return nil
    end

    def process_rewrites
      req   = @params[:req]
      count = 0
      each_point_rewrite do |point, template|
        entry = req[point]
        value = entry.value
        wrap_proton_errors { entry.value = template.render('val' => value) }
        if Thread.current[:liquid_matched]
          count += 1
          break
        end
      end
      App.logger.info "#{count} rewrites was applyed" if count > 0
    rescue => e
      App.logger.error(e)
      App.logger.error 'Exception occured while processing rewrites, skip rewrites'
    end

    attr_reader :params

    def charset
      @params[:entry_value_charset]
    end

    def entry_value
      @params[:entry_value]
    end

    def skip_etcd_errors
      yield
    rescue RpsLimit::EtcdError => ex
      App.logger.error(ex)
    end

    def http(params)
      RequestCount.count += 1

      http_params = parse(params)

      @job && @job.heartbeat

      result = ScannerExtensions::Helpers::Http.request(http_params)

      lock  = @params[:lock]
      locks = @params[:locks]

      Kernel.sleep 60.0 / lock.rpm if lock
      if locks
        @last_locks_heartbeat ||= 0
        if Time.now.to_i - @last_locks_heartbeat > 60
          locks.each { |lock| skip_etcd_errors { lock.heartbeat } }
        end
        @last_locks_heartbeat = Time.now.to_i
      end

      @job && @job.heartbeat

      result
    end

    def curl_helper(params)
      http_params             = parse(params)
      http_params[:post_data] = http_params[:body]
      http_params[:headers].delete('X-Wallarm-Scanner-Info')
      VulnTemplates::Helpers.curl(http_params)
    end

    def desc
      proto  = @params[:use_ssl] ? 'https' : 'http'
      domain = (host || '').normalize_enconding.split(':')[0]
      "#{domain} #{proto}://#{@params[:ip]}:#{@params[:port]}"
    end

    def to_s
      "#{host}@#{@params[:ip]}:#{@params[:port]}"
    end

    def raw_req
      req = @params[:req]
      raw = req.to_raw

      raw[:uri] ||= '/'
      raw
    rescue => ex
      App.logger.error(ex)
      raise ProtonError
    end

    def host
      raw_req[:headers]['HOST'].flatten.first.to_s
    rescue
      return nil
    end

    private

    def parse(params)
      marker = nil

      case entry_method
      when :raw
        marker = SecureRandom.hex(16)
        wrap_proton_errors { @params[:entry].value = marker }
      when :get_pollution
        # nothing to do
      else
        wrap_proton_errors { @params[:entry].value = params[:value] }
      end

      raw = raw_req

      ip   = @params[:ip]
      port = @params[:port]
      uri  = process_uri_rewrites(raw[:uri]) || raw[:uri]
      body = raw[:body]

      if entry_method == :raw
        value = params[:value]
        value = value.gsub(' ', '+')
        uri.sub!(marker, value)
        body.sub!(marker, value) unless body.nil?
      end

      uri = '/' + uri if uri[0] != '/'

      if entry_method == :get_pollution
        parts     = uri.split('#')
        parts[0] += "&#{@params[:entry].name}=#{CGI.escape(params[:value])}"
        uri = parts.join('#')
      end

      @params[:uri]  = uri
      @params[:body] = body

      http_params = {
        use_ssl: @params[:use_ssl],
        host: ip,
        port: port,
        url: uri,
        body: body
      }.merge(params)

      # Use first host in array
      vhost = begin
                [raw[:headers]['HOST']].flatten.first.to_s
              rescue
                nil
              end
      if vhost
        http_params[:vhost] = vhost
        @params[:domain]    = vhost
      end

      @params[:method]     = raw[:method].to_s
      http_params[:method] = raw[:method].to_s.downcase.to_sym
      http_params[:request_class] =
        case http_params[:method]
        when :get
          Net::HTTP::Get
        when :post
          Net::HTTP::Post
        when :put
          Net::HTTP::Put
        when :head
          Net::HTTP::Head
        when :options
          Net::HTTP::Options
        when :patch
          Net::HTTP::Patch
        when :copy
          Net::HTTP::Copy
        when :delete
          Net::HTTP::Delete
        when :lock
          Net::HTTP::Lock
        when :unlock
          Net::HTTP::Unlock
        when :move
          Net::HTTP::Move
        when :trace
          Net::HTTP::Trace
        else
          raise "Invalid method '#{raw[:method]}'"
        end

      # Delete auth cookies or not
      exclude = []

      exclude << 'USER-AGENT' unless @params[:point].start_with?([[:header, 'USER-AGENT']])
      exclude << 'ACCEPT-ENCODING' unless @params[:point].start_with?([[:header, 'ACCEPT-ENCODING']])
      if @params[:preserve_auth] != true
        exclude << 'COOKIE' unless @params[:point].start_with?([[:header, 'COOKIE']])
        exclude << 'AUTHORIZATION'
      end

      # Use http_params[:vhost]
      exclude += ['HOST']

      headers = {}
      raw[:headers] && raw[:headers].reject do |name, _values|
        exclude.include?(name)
      end.each do |name, values|
        next if /^X-Wallarm-.*/i =~ name

        headers[name] = [values].flatten.first.to_s
      end
      headers['User-Agent'] = 'Wallarm attack-rechecker (v1.x)' unless @params[:point].start_with?([[:header, 'USER-AGENT']])
      headers['X-Wallarm-Scanner-Info'] = Base64.strict_encode64(
        {
          type: :attack_rechecker,
          queue: App.config.queue,
          detect_type: @params[:info][:detect_type],
          extension: @params[:info][:extension],
          hit_id: @params[:info][:hit_id],
          point: @params[:info][:point]
        }.to_json
      )
      http_params[:headers]  = headers
      http_params[:protocol] = http_params[:use_ssl] ? 'https' : 'http'
      http_params[:follow_redirect] = 5

      if under_test?
        http_params[:timeout] = 2
        http_params[:vhost] = '127.0.0.1' unless http_params[:vhost]
      end

      http_params
    end
  end
end
