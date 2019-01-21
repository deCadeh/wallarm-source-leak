module FastDsl
  module Blocks
    # for which baselines detect is applicable
    class Match
      def initialize(params)
        @regexp  = {}
        @empty   = {}
        @missing = {}

        (params || {}).each do |k, v|
          regexp = Regexp.new(k)
          case v
          when nil
            @missing[regexp] = nil
          when ''
            @empty[regexp] = ''
          else
            @regexp[regexp] = Regexp.new(v)
          end
        end
      end

      def applicable?(baseline)
        check_regexp(baseline) && check_empty(baseline) && check_missing(baseline)
      end

      private

      def check_regexp(baseline)
        @regexp.each do |point_regexp, match|
          found = false
          baseline.each_point_value do |point, value|
            next unless point_regexp =~ point

            value =~ match ? found = true : (return false)
          end
          return false unless found
        end
        true
      end

      def check_empty(baseline)
        @empty.each do |point_regexp, _v|
          found = false
          baseline.each_point_value do |point, value|
            next unless point_regexp =~ point

            value == '' ? found = true : (return false)
          end
          return false unless found
        end
        true
      end

      def check_missing(baseline)
        @missing.each do |point_regexp, _v|
          baseline.each_point_value do |point, _value|
            return false if point_regexp =~ point
          end
        end
        true
      end
    end
  end
end
