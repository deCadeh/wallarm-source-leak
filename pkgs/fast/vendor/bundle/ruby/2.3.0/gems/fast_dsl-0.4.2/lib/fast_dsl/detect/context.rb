module FastDsl
  class Detect
    # we use this context to link different detect steps
    class Context
      attr_accessor(
        :baseline,
        :payload_checks,
        :vulns,
        :oob_callbacks,
        :meta_info
      )

      def initialize(opts = {})
        @baseline = opts.fetch(:baseline)

        @payload_checks = []
        @vulns          = []
        @oob_callbacks  = []
      end

      def vuln?
        @vulns.any?
      end
    end
  end
end
