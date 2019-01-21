require 'securerandom'

module FastDsl
  class Detect
    # describes what have we have sent and received
    class PayloadCheck
      attr_accessor(
        :origin_payload,
        :payload,
        :insertion_point_value,
        :response,
        :str_marker,
        :calc_marker,
        :dns_marker,
        :origin_calc_marker
      )

      def initialize(opts)
        @charset = [('a'..'z'), ('0'..'9')].map(&:to_a).flatten

        @origin_payload = opts.fetch(:payload)

        generate_markers(@origin_payload)
      end

      def perform(opts)
        raise if @response

        @insertion_point_value = insert(
          payload,
          opts.fetch(:insertion_method),
          opts.fetch(:origin_insertion_point_value)
        )

        @response = opts.fetch(:baseline).request(value: @insertion_point_value)
      end

      private

      def generate_markers(payload_template)
        @dns_marker = nil
        @payload    = payload_template

        if @payload.index('DNS_MARKER')
          @dns_marker = FastDsl.oob_dns.create
          @payload    = @payload.gsub('DNS_MARKER', @dns_marker)
        end

        @str_marker = generate_str_marker
        @payload    = @payload.gsub('STR_MARKER', @str_marker)

        @origin_calc_marker = generate_calc_marker
        @payload            = @payload.gsub('CALC_MARKER', @origin_calc_marker)
      end

      def generate_str_marker
        'w' + Array.new(6).map { @charset[SecureRandom.random_number(@charset.size)] }.join
      end

      def generate_calc_marker
        n1 = 100 + SecureRandom.random_number(900)
        n2 = 100 + SecureRandom.random_number(900)
        @calc_marker = (n1 * n2).to_s
        "#{n1}*#{n2}"
      end

      def insert(payload, insertion_method, origin_insertion_point_value)
        case insertion_method
        when 'replace'
          payload
        when 'prefix'
          payload + origin_insertion_point_value
        when 'postfix'
          origin_insertion_point_value + payload
        when 'random'
          size = origin_insertion_point_value.size
          origin_insertion_point_value.insert(rand(size), payload)
        else
          raise
        end
      end
    end
  end
end
