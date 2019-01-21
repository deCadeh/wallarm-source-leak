module FastDsl
  module Blocks
    # what should we send to server as payload
    class Generate
      class << self
        def schema
          Dry::Validation.Schema do
            configure { predicates(Schema::Predicates) }

            required('payload').each(:str?, :filled?)

            optional('into').value(:str?, :regexp?)

            optional('method').each(
              included_in?: %w[postfix prefix replace random]
            )
          end
        end
      end

      def initialize(params = {})
        default_method = params ? ['replace'] : ['postfix']

        params ||= {}
        @payload = params.fetch('payload', [''])
        @into    = params['into'] ? Regexp.new(params['into']) : /.*/
        @method  = params['method'] || default_method
      end

      def applicable?(baseline)
        baseline.insertion_point =~ @into
      end

      def run(ctx)
        @payload.each do |payload|
          @method.each do |method|
            payload_check = FastDsl::Detect::PayloadCheck.new(payload: payload)

            payload_check.perform(
              baseline:                     ctx.baseline,
              insertion_method:             method,
              origin_insertion_point_value: ctx.baseline.insertion_point_value
            )

            ctx.payload_checks << payload_check
          end
        end
      end
    end
  end
end
