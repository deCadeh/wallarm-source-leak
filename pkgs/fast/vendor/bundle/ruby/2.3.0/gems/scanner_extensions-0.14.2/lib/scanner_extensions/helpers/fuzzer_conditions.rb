module ScannerExtensions
  module Helpers
    class FuzzerConditions
      InvalidPolicies = Class.new(RuntimeError)

      class Condition
        attr_accessor :type, :f

        def initialize(type, f)
          @type = type
          @f    = f
        end
      end

      attr_accessor :regexps

      def initialize(policies, defaults = false)
        policies = policies.split(',') if policies.is_a? String

        @regexps = []
        @metrics = {
          status:         nil,
          length:         nil,
          time:           nil,
          length_diff:    nil,
          time_diff:      nil,
          dom_diff:       nil,
          regexp:         nil,
          anomalies:      nil,
          timeout_errors: nil
        }

        parsers = {
          status:         method(:parse_numbers),
          length:         method(:parse_numbers),
          time:           method(:parse_numbers),
          length_diff:    method(:parse_numbers),
          time_diff:      method(:parse_numbers),
          dom_diff:       method(:parse_numbers),
          regexp:         method(:parse_regexp),
          timeout_errors: method(:parse_numbers),
          anomalies:      method(:parse_numbers)
        }

        last_name = nil
        policies.each do |policy|
          next if policy == ''
          name, opt = policy.split(':')
          name      = name.to_sym
          # parse new policy
          if name && opt
            raise InvalidPolicies unless @metrics.keys.include?(name)
            last_name = name

            @metrics[name] ||= []
            @metrics[name]  << parsers[name].call(opt)
          # next opt for previous policy
          elsif last_name
            opt = policy
            @metrics[last_name] ||= []
            @metrics[last_name]  << parsers[last_name].call(opt)
          else
            raise InvalidPolicies
          end
        end
        make_defaults if defaults
      end

      def accept?(opts, keys = nil)
        opts = Marshal.load(Marshal.dump(opts))
        keys = opts.keys unless keys

        # Handle related params
        [[:time, :time_diff], [:length, :length_diff]].each do |pair|
          p1, p2 = pair

          if keys.include?(p1) && keys.include?(p2)
            # if has only one condition for related params
            # then do not check empty condition
            unless @metrics.key?(p1) ^ @metrics.key?(p2)
              if @metrics.key?(p1)
                opts.delete(p2)
              else
                opts.delete(p1)
              end
            end
          end
        end

        opts.each do |k,v|
          next unless keys.include? k
          return true if check_field(k, opts)
        end
        return false
      end

      def check_field(field, opts)
        value = opts[field]
        res   = true

        return res unless @metrics[field]

        @metrics[field].each do |cond|
          next unless cond.type == :or
          res = false
          if cond.f.call(value)
            res = true
            break
          end
        end

        @metrics[field].each do |cond|
          next unless cond.type == :and
          return false unless cond.f.call(value)
        end

        return res
      end

      def reject?(opts)
        opts.each do |k,v|
          return true if check_field_skip_null(k, opts)
        end
        return false
      end

      def check_field_skip_null(field, opts)
        return false if !@metrics[field] || @metrics[field] == []
        return check_field(field, opts)
      end

      private

      def make_defaults
        unless @metrics[:status]
          @metrics[:status] = [parse_numbers('400')]
        end
      end

      def parse_regexp(str)
        r = Regexp.new(str.delete("'"))
        @regexps << r
        Condition.new(:or, ->(str) { r =~ str })
      rescue
        raise InvalidPolicies
      end

      def parse_numbers(str)
        case str
        when /\A([0-9]*)\+\z/
          number = Regexp.last_match[1].to_i
          Condition.new(:or, ->(n) { n >= number })
        when /\A>=([0-9]*)\z/
          number = Regexp.last_match[1].to_i
          Condition.new(:or, ->(n) { n >= number })
        when /\A<=([0-9]*)\z/
          number = Regexp.last_match[1].to_i
          Condition.new(:or, ->(n) { n <= number })
        when /\A>([0-9]*)\z/
          number = Regexp.last_match[1].to_i
          Condition.new(:or, ->(n) { n > number })
        when /\A<([0-9]*)\z/
          number = Regexp.last_match[1].to_i
          Condition.new(:or, ->(n) { n < number })
        when /\A!([0-9]*)\z/
          number = Regexp.last_match[1].to_i
          Condition.new(:and, ->(n) { n != number })
        when /\A([0-9]*)\z/
          number = Regexp.last_match[1].to_i
          Condition.new(:or, ->(n) { n == number })
        else
          raise InvalidPolicies
        end
      end
    end
  end
end
