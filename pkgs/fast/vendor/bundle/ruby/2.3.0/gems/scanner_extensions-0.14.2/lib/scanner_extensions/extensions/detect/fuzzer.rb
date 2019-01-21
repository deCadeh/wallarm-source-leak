require 'cgi'

module ScannerExtensions
  module Extensions
    class Fuzzer < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :fuzzer

        @defaults = {
          timeout:        15,
          reliable:       3,
          diff:           0.35,
          slice:          16,
          html_deep:      16,
          standart_sleep: 1.0,
          max_sleep:      4.0,
          bytes:          (0..255).to_a.shuffle
        }
      end

      def run(object, params)
        total_anomalies = {}

        Thread.current[:timeout_errors] = 0
        object.fuzzer_policies.each do |policy|
          process_policy(object, params, policy, total_anomalies)
        end

        total_anomalies.size > 0 ? total_anomalies : nil
      end

      def process_policy(object, params, policy, total_anomalies)
        entry_value = object.entry_value.to_s
        rparams     = @defaults.merge(params)

        type = policy[0]
        case type
        when 'all'
          policy = policy.dup
          [
            'replace_all',
            'append',
            'prepend',
            'replace',
            'insert_rand',
            'replace_rand'
          ].each do |name|
            policy[0] = name
            if process_policy(object, params, policy, total_anomalies)
              return true
            end
          end
        when 'replace_all'
          entry_f = ->(v) { v }
          policy[1] && rparams[:slice] = policy[1]
          return run_policy(object, rparams, entry_f, total_anomalies)
        when 'append'
          entry_f = ->(v) { entry_value + v }
          policy[1] && rparams[:slice] = policy[1]
          return run_policy(object, rparams, entry_f, total_anomalies)
        when 'prepend'
          entry_f = ->(v) { v + entry_value }
          policy[1] && rparams[:slice] = policy[1]
          return run_policy(object, rparams, entry_f, total_anomalies)
        when 'replace'
          policy[1] && rparams[:slice] = policy[1]
          slice = rparams[:slice].to_i
          if slice > 0
            entry_f = ->(v) { v + (entry_value[slice .. -1]||'') }
          else
            rparams[:slice] = slice = -slice
            entry_f = ->(v) { entry_value[0 ... -slice] + v }
          end
          policy[2] && rparams[:slice] = policy[2]
          return run_policy(object, rparams, entry_f, total_anomalies)
        when 'insert_rand'
          entry_f = ->(v) { String.new(entry_value).insert(rand(entry_value.size+1), v) }
          policy[1] && rparams[:slice] = policy[1]
          return run_policy(object, rparams, entry_f, total_anomalies)
        when 'replace_rand'
          policy[1] && rparams[:slice] = policy[1]
          slice = rparams[:slice]
          entry_f = ->(v) do
            diff = entry_value.size - v.size
            if diff>=1
              id = rand(diff + 1)
              entry_value[0...id] + v + entry_value[(id + v.size)..-1]
            else
              v
            end
          end
          return run_policy(object, rparams, entry_f, total_anomalies)
        end
        return false
      end

      def run_policy(object, params, entry_f, total_anomalies)
        params[:slice] = params[:slice].to_i
        return if params[:slice]<=0
        single = (params[:slice]==1)

        charset = object.charset || :alpha

        bytes  = params[:bytes].shuffle
        origin = []
        case charset
        when :num
          origin = ('0'..'9').to_a.map(&:ord)
        else
          origin = ('a'..'z').to_a.map(&:ord)
        end
        bytes  = bytes - origin
        slices = bytes.each_slice(params[:slice])

        result = {}

        origin_val = origin[0]
        origin     = stat(object, entry_f.call(origin_val.chr), params)

        return unless origin

        slices.each do |slice|
          unless single
            slice_res = stat(object, entry_f.call(slice.map(&:chr).join), params)
            next unless slice_res
          end
          if single || slice_res != origin
            unless single
              keys        = slice_res.anomaly_keys(origin)
              policy_hash = slice_res.to_h_policy(origin)

              if object.has_conditions
                # force accept original regexps
                if slice_res.errors.empty? && !keys.include?(:errors)
                  next unless object.include_conditions.accept?(policy_hash, keys)
                end

                next   if object.exclude_conditions.reject?(policy_hash)
                return if object.hardstop_conditions.reject?(policy_hash)
                return if object.hardstop_conditions.reject?(
                  timeout_errors: Thread.current[:timeout_errors]
                )
              end
            end

            slice.each do |chr|
              chr_res = stat(object, entry_f.call(chr.chr), params)
              next unless chr_res

              keys        = chr_res.anomaly_keys(origin)
              policy_hash = chr_res.to_h_policy(origin)

              if object.has_conditions
                # force accept original regexps
                if chr_res.errors.empty? && !keys.include?(:errors)
                  next unless object.include_conditions.accept?(policy_hash, keys)
                end

                next   if object.exclude_conditions.reject?(policy_hash)
                return if object.hardstop_conditions.reject?(policy_hash)
                return if object.hardstop_conditions.reject?(
                  timeout_errors: Thread.current[:timeout_errors]
                )
              end

              if chr_res != origin
                result[chr] = chr_res
              end
            end
          end
        end

        result_copy = result.dup

        if object.has_conditions
          return if object.hardstop_conditions.reject?(anomalies: result.size)
        end

        union_res = {}

        while result.size>0
          k = result.first.first
          v = result.delete(k)
          array = [k]
          result.each do |_k, _v|
            if v==_v
              array << _k
              result.delete(_k)
            end
          end
          union_res[array] = v
        end

        # server should be stable
        check_origin = stat(object, entry_f.call(origin_val.chr), params)

        if check_origin == origin && (origin.errors.size > 0 || union_res.size > 0)
          total_anomalies.merge!(origin.anomalies)
          origin_row = origin.to_row(sprintf("0x%02X", origin_val))
          anomalies  = []
          union_res.each do |k, v|
            bytes = ScannerExtensions::Helpers::UnionBytes.format(k)

            anomalies << v.to_row(bytes, origin)
            total_anomalies.merge!(v.anomalies(origin))
          end

          anomalies.sort!

          curl_args      = nil
          template       = nil
          html_rows_args = {}

          # found regexp into origin request and no anomalies yet
          if result_copy.keys.empty?
            template       = '/info/fuzzer/baseline'
            curl_args      = { exploit_example: object.curl_helper(:value => origin_val.chr) }
            html_rows_args = {}
          else
            template = '/info/fuzzer'
            curl_args = {
              curl1: object.curl_helper(:value => origin_val.chr),
              curl2: object.curl_helper(:value => result_copy.keys.sample.chr)
            }
            html_rows_args = { html_rows: anomalies }
          end

          object.vuln(
            extension: 'fuzzer',
            template:  template,
            binding:   :protocol,
            args: {
              anomalies:     total_anomalies.select { |k, v| v }.keys.map(&:to_s).sort,
              html_baseline: origin_row
            }.merge(curl_args).merge(html_rows_args)
          )
          return true
        end
        return false
      end

      private

      class Metric
        attr_accessor :size
        attr_accessor :time
        attr_accessor :status
        attr_accessor :errors
        attr_accessor :dom
        attr_accessor :body

        attr_accessor :value

        def initialize(params, value)
          @params = params
          @value  = value
        end

        def anomaly_keys(object)
          res  = []

          res += [:time, :time_diff]     if diff_in_time(object)
          res += [:status]               if diff_in_status(object)
          res += [:length, :length_diff] if diff_in_size(object)
          res += [:dom_diff]             if diff_in_dom(object)
          res += [:regexp]               if diff_in_errors(object)

          return res
        end

        def to_h_policy(object)
          d1 = @dom.contains(object.dom, @params[:html_deep]) || 0
          d2 = object.dom.contains(@dom, @params[:html_deep]) || 0
          dom_diff = [d1, d2].max

          {
            time:        @time,
            status:      @status,
            length:      @size,
            time_diff:   (@time-object.time).abs,
            length_diff: (@size-object.size).abs,
            dom_diff:    dom_diff,
            regexp:      @body
          }
        end

        def ==(object)
          cmp(@size, object.size, @params[:diff]) &&
          cmp(@time, object.time, @params[:diff]) &&
          @status == object.status                &&
          @errors.sort == object.errors.sort      &&
          (
            @dom != 0 && object.dom != 0 &&
            @dom.crc_hash(@params[:html_deep]) == object.dom.crc_hash(@params[:html_deep])
          )
        end

        def to_h(object=nil)
          r = {
            :time   => @time   == -1     ? 'N/A' : @time.to_f.round(2),
            :status => @status == -1     ? 'N/A' : @status,
            :errors => @errors.size == 0 ? 'N/A' : @errors[0],
            :size   => @size
          }
          if object
            v1 = @dom.contains(object.dom, @params[:html_deep]) || 0
            v2 = object.dom.contains(@dom, @params[:html_deep]) || 0
            v  = [v1,v2].max
            r[:dom_diff] = v
          else
            r[:dom_diff] = 'N/A'
          end
          r
        end

        def anomalies(object = nil)
          anomalies = {}
          anomalies[:error] = true if @errors.size > 0

          return anomalies unless object

          anomalies[:status] = true if diff_in_status(object)
          anomalies[:size]   = true if diff_in_size(object)
          anomalies[:time]   = true if diff_in_time(object)
          anomalies[:dom]    = true if diff_in_dom(object)
          anomalies[:error]  = true if diff_in_errors(object)

          anomalies
        end

        def to_row(bytes, object = nil)
          h  = self.to_h(object)

          r  = "<tr>"
          r += "<td>#{bytes}</td>"
          if object
            r += build_html(h[:status],   object, method(:diff_in_status))
            r += build_html(h[:size],     object, method(:diff_in_size))
            r += build_html(h[:time],     object, method(:diff_in_time))
            r += build_html(h[:errors],   object, method(:diff_in_errors))
            r += build_html(h[:dom_diff], object, method(:diff_in_dom))
          else
            r += build_html_simple(h[:status])
            r += build_html_simple(h[:size])
            r += build_html_simple(h[:time])
            r += build_html_simple(h[:errors])
            r += build_html_simple(h[:dom_diff])
          end
          r += "</tr>"
          r
        end

        private

        def build_html(val, obj, method)
          if method.call(obj)
            build_html_colored(val)
          else
            build_html_simple(val)
          end
        end

        def build_html_simple(val)
          "<td>#{val}</td>"
        end

        def build_html_colored(val)
          "<td><font color=red>#{val}</font></td>"
        end

        def diff_in_size(object)
          !cmp(@size, object.size, @params[:diff])
        end

        def diff_in_time(object)
          !cmp(@time, object.time, @params[:diff])
        end

        def diff_in_status(object)
          @status != object.status
        end

        def diff_in_errors(object)
          @errors.sort != object.errors.sort
        end

        def diff_in_dom(object)
          @dom.crc_hash(@params[:html_deep]) != object.dom.crc_hash(@params[:html_deep])
        end

        def cmp(t1, t2, delta)
          max = [t1, t2].max.to_f
          min = [t1, t2].min.to_f
          max = 1.0 if max == 0
          min = 1.0 if min == 0
          return (1.0 - min/max < delta)
        end
      end

      def stat(object, val, params)
        origin = get(object,  val, params)

        (params[:reliable]-1).times do
          test = get(object, val, params)
          return nil unless test==origin
        end

        return origin
      end

      def get(object, val, params)
        value  = val
        startt = Time.now.to_f
        resp   = object.http(value: value, timeout: params[:timeout], open_timeout: params[:open_timeout])
        endt   = Time.now.to_f

        if resp.nil?
          metric        = Metric.new(params, val.ord)

          body          = ''
          metric.size   = 0
          metric.status = -1
          metric.dom    = 0
          metric.errors = []
          metric.time   = -1

          Thread.current[:timeout_errors] += 1

          return metric
        end

        metric        = Metric.new(params, val.ord)

        body          = resp.body || ''
        body          = body.normalize_enconding
        headers       = ''
        resp.to_hash.each { |k,v| headers += k.upcase + ': ' + v.join(';') + "\n" }

        metric.body   = headers + body
        metric.size   = body.size
        metric.status = resp.code.to_i
        metric.dom    = ScannerExtensions::Helpers::Gumbo.parse body
        metric.time   = endt - startt
        metric.time   = params[:standart_sleep] if metric.time < params[:max_sleep]
        if object.has_conditions
          metric.errors = ScannerExtensions::Helpers::Errors.find(body, object.include_conditions.regexps)
        else
          metric.errors = ScannerExtensions::Helpers::Errors.find(body)
        end

        return metric
      end
    end
  end
end
