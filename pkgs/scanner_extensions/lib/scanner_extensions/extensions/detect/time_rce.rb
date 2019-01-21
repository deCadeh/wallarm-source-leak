module ScannerExtensions
  module Extensions
    class TimeRce < BaseExtension; end

    class FastTimeRce < TimeRce
      def initialize
        super
        @components = :fast
        @payloads = [
          %{sleep %<time>s ||`sleep %<time>s` #' |sleep %<time>s||`sleep %<time>s` #\" |sleep %<time>s},
          %{sleep %<time>s &&`sleep %<time>s` #' &sleep %<time>s&&`sleep %<time>s` #\" &sleep %<time>s},
        ]
      end
    end

    class TimeRce < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :rce
        @components          = :rechecker

        @defaults = {
          base_time: 5.0
        }

        @payloads = [
          %{sleep %<time>s ||`sleep %<time>s` #' |sleep %<time>s||`sleep %<time>s` #\" |sleep %<time>s},
          %{sleep %<time>s &&`sleep %<time>s` #' &sleep %<time>s&&`sleep %<time>s` #\" &sleep %<time>s},
          %{$(sleep${IFS}%<time>s)},
          %{&sleep(%<time>s);},
          %{;sleep(%<time>s);'},
          %{\\";sleep(%<time>s);#},
          %{';sleep(%<time>s);#},
          %{{sleep,%<time>s}}
        ]
      end

      def get_time(time, max_time, params)
        start  = Time.now.to_f
        test   = params[:object].http(
          url_code: false,
          value: value(time),
          timeout: max_time,
          open_timeout: max_time
        )
        endt = Time.now.to_f
        return nil if test.nil?
        return nil if test.body.nil?
        return nil if test.code.to_i != 200
        endt - start
      end

      def run(object, params)
        params = @defaults.merge(params)
        detector = SleepKmeans.new(object, @payloads, params)
        detector.perform_detect
        if detector.detect_anomaly?
          curl1 = object.curl_helper(
            url_code: false,
            value: format(detector.vuln_payload, time: detector.base_time)
          )
          object.vuln(
            extension: 'time_rce',
            template: '/rce',
            binding: :protocol,
            args: {
              # curl1: curl1,
              # time1: detector.normal_response_time.round(3),
              # curl2: curl2,
              # time2: detector.anomaly_response_time.round(3),
              exploit_example: curl1
            }
          )
          return
        end
      end
    end
  end
end
