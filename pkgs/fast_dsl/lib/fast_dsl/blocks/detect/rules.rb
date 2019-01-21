module FastDsl
  module Blocks
    class Detect
      module Rules
        # Base class for any rule
        class BaseRule
          def type
            :sync
          end

          def exploit_stamp(pos, data)
            size = 100

            pos ? data[[pos - size / 2, 0].max, size] : data[0, size]
          end

          def make_regexp(str, opts)
            str   = str.dup
            check = opts.fetch(:payload_check)

            str.gsub!('STR_MARKER', check.str_marker) if check.str_marker

            str.gsub!('CALC_MARKER', check.calc_marker) if check.calc_marker

            if check.dns_marker
              replace = check.dns_marker.gsub('.', '\.')
              str.gsub!('DNS_MARKER', replace)
            end

            Regexp.new(str)
          end
        end

        # Finds oob dns requests
        class OobDns < BaseRule
          attr_reader :marker

          def type
            :async
          end

          def run(opts)
            token = opts.fetch(:payload_check).dns_marker
            return false unless token

            @marker = token
            array = FastDsl.oob_dns.get(token)
            array.empty? ? nil : array
          end
        end

        # Finds any marker in body
        class BodyMarker < BaseRule
          def initialize(regexp)
            @regexp = regexp
          end

          def marker
            @regexp
          end

          def run(opts)
            offset = opts.fetch(:body) =~ make_regexp(@regexp, opts)
            return unless offset

            exploit_stamp(offset, opts.fetch(:body))
          end
        end

        # Finds any marker in headers by header => value
        class HeadersMarker < BaseRule
          def initialize(key, val)
            @key = key
            @val = val
          end

          def marker
            "#{@key}: #{@val}"
          end

          def run(opts)
            key = make_regexp(@key, opts)
            val = make_regexp(@val, opts)

            opts.fetch(:headers).each do |k, v|
              next unless k =~ key && v =~ val

              return "#{k}: #{v}\n"
            end

            nil
          end
        end

        # Finds any marker in headers by fullscan
        class HeadersFullscanMarker < BaseRule
          def initialize(regexp)
            @regexp = regexp
          end

          def marker
            @regexp
          end

          def run(opts)
            offset = opts.fetch(:all_headers) =~ make_regexp(@regexp, opts)
            return unless offset

            exploit_stamp(offset, opts.fetch(:all_headers))
          end
        end

        # Detects anomal status
        class Status < BaseRule
          def initialize(status)
            @regexp = "\\A#{status}"
          end

          def marker
            @regexp
          end

          def run(opts)
            return unless opts.fetch(:status) =~ Regexp.new(@regexp)

            exploit_stamp(0, opts.fetch(:body))
          end
        end
      end
    end
  end
end
