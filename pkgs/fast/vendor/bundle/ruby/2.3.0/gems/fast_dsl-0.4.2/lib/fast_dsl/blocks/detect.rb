require_relative './detect/schema'
require_relative './detect/parser'
require_relative './detect/rules'
require_relative './detect/html_rules'

module FastDsl
  module Blocks
    # what should we search into server's response to find vuln
    class Detect
      extend Schema

      def initialize(detect)
        @parsed = Parser.new(detect)
        @rules  = @parsed.rules
      end

      def run(ctx)
        run_sync_checks(ctx)
        prepare_async_checks(ctx) if @rules.map(&:class).include?(Rules::OobDns)
      end

      private

      def run_sync_checks(ctx)
        ctx.payload_checks.each do |payload_check|
          next unless payload_check.response

          body = Helpers.normalize_enconding(payload_check.response.body || '')
          dom  = Helpers.parse_html(body)

          headers = Helpers.normalize_hash_enconding(
            Hash[payload_check.response.each_capitalized.to_a]
          )

          all_headers = ''
          headers.each { |k, v| all_headers += k + ': ' + v + "\n" }

          opts = {
            payload_check: payload_check,
            status:        payload_check.response.code,
            body:          body,
            dom:           dom,
            headers:       headers,
            all_headers:   all_headers
          }

          @rules.select { |rule| rule.type == :sync }.each do |rule|
            stamp = rule.run(opts)
            next unless stamp

            vuln = FastDsl::Detect::Vuln.new(
              type:                  :sync,
              trigger_name:          rule.class.to_s.split('::').last,
              payload_check:         payload_check,
              payload:               payload_check.payload,
              insertion_point_value: payload_check.insertion_point_value,
              marker:                rule.marker,
              exploit_stamp:         stamp
            )

            ctx.vulns << vuln

            return true
          end
        end
      end

      def prepare_async_checks(ctx)
        ctx.oob_callbacks << proc do
          found = false

          ctx.payload_checks.each do |payload_check|
            @rules.select { |rule| rule.type == :async }.each do |rule|
              proof = rule.run(payload_check: payload_check)

              next unless proof

              vuln = FastDsl::Detect::Vuln.new(
                type:                  :async,
                trigger_name:          rule.class.to_s.split('::').last,
                payload_check:         payload_check,
                payload:               payload_check.payload,
                insertion_point_value: payload_check.insertion_point_value,
                marker:                rule.marker,
                oob_triggered_ip:      proof
              )

              ctx.vulns << vuln

              found = true

              break
            end

            break if found
          end

          ctx
        end
      end
    end
  end
end
