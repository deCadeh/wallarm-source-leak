require 'request_count'

class BaselineCheckJob
  # Extend BaselineCheckJob to handle policies
  module RunExtensionsHelper
    def run_extension(ext, object)
      opts = { open_timeout: 10 }

      xml_bytes = [9, 10, 13] + (32..255).to_a
      is_xml    = object.params[:point].to_a.to_s.include?(':xml, :xml_tag,')

      case ext
      when ScannerExtensions::Extensions::Fuzzer
        opts[:bytes] = xml_bytes if is_xml
        App.logger.info('Use restricted set of bytes due to xml point') if is_xml
        res   = ext.run(object, opts)
        res ||= {}
        return { fuzzer: true }.merge(res)
      else
        ext.run(object, opts)
        return nil
      end
    rescue BaselineCheckTestRunIsGone => ex
      raise ex
    rescue => detail
      App.logger.error(detail)
      return nil
    end

    def run_oob_callbacks(entries, job, last_oob_callback_run_time)
      if last_oob_callback_run_time + 60 > Time.now.to_i
        return last_oob_callback_run_time
      end

      sleep 1

      entries.each do |entry|
        entry.each do |object|
          begin
            (object.oob_callbacks || []).each do |callback|
              callback.call
              job.heartbeat
            end
          rescue => detail
            App.logger.error(detail)
          ensure
            object.oob_callbacks = []
          end
        end
      end

      Time.now.to_i
    end

    def run_extensions(entries, ssl_connection_params, policy, job, lock = nil)
      last_oob_callback_run_time = Time.now.to_i
      anomalies = nil
      entries.each do |entry|
        entry.each_with_index do |object, i|
          object.entry_method  = :normal
          object.oob_callbacks = []
          (policy[:type_include] - policy[:type_exclude] + [:custom]).each do |detect_type|
            point = object.params[:point]
            msg = "Running #{detect_type.to_s.upcase} tests for the request parameter '#{point}'"
            App.log(level: :info, msg: msg)

            ObjectHelpers.get_extensions(
              detect_type,
              object.params[:point],
              :fast
            ).each do |ext|
              next if ext.respond_to?(:applicable?) && !ext.applicable?(object)

              use_ssl = ssl_connection_params[i]
              use_ssl.each do |ssl|
                last_oob_callback_run_time = run_oob_callbacks(entries, job, last_oob_callback_run_time)

                object.params[:use_ssl] = ssl

                object.params[:info][:detect_type] = detect_type
                object.params[:info][:hit_id]      = job['es_hit_id']
                object.params[:info][:point]       = object.params[:point]
                object.params[:info][:extension]   = ext.class.to_s

                if lock
                  object.params[:lock]  = lock
                  object.params[:locks] = [lock]
                end

                object.job = job

                point = object.params[:point]
                App.logger.info("Running ssl=#{ssl} #{ext.class} for #{object}##{point}")

                job.heartbeat

                RequestCount.count = 0

                res = run_extension(ext, object)
                if res
                  anomalies ||= { fuzzer: true }
                  anomalies.merge!(res)
                end

                BaselineCheckAPI.update_counters(
                  job['baseline_check_id'],
                  RequestCount.count,
                  1
                )

                break unless object.vulns.empty?
              end

              sync_vulns_with_api(object, job) unless object.vulns.empty?
            end
          end
        end
      end

      anomalies
    end
  end
end
