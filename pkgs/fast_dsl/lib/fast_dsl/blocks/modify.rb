module FastDsl
  module Blocks
    # how we should modify baseline before send it
    class Modify
      def initialize(params)
        @map = params.dup if params
      end

      def run(ctx)
        return unless @map

        @map.each { |k, v| ctx.baseline.set_point_value(k, v) }
      end
    end
  end
end
