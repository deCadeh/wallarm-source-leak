module FastDsl
  module Schema
    # helpers for FastDsl::Shema
    module Predicates
      include Dry::Logic::Predicates

      predicate(:regexp?) { |value| valid_regexp?(value) }

      predicate(:hash?) do |value|
        value.is_a?(Hash)
      end

      predicate(:str_hash?) do |value|
        value.is_a?(Hash) && value.all? do |k, v|
          k.is_a?(String) && v.is_a?(String)
        end
      end

      predicate(:regexp_hash?) do |value|
        value.is_a?(Hash) && value.all? do |k, v|
          valid_regexp?(k) && (v.nil? || valid_regexp?(v))
        end
      end

      predicate(:regexp_or_array?) do |value|
        value.is_a?(String) && valid_regexp?(value) || value.is_a?(Array)
      end

      predicate(:regexp_or_array_of_regexp_hash?) do |value|
        value.is_a?(String) && valid_regexp?(value) ||
          value.is_a?(Array) && value.any? && value.all? do |e|
            e.is_a?(Hash) && e.all? do |k, v|
              valid_regexp?(k) && valid_regexp?(v)
            end
          end
      end

      predicate(:int_or_string?) do |value|
        value.is_a?(Numeric) || value.is_a?(String) && !value.empty?
      end

      def self.valid_regexp?(str)
        Regexp.new(str)
      rescue
        false
      end

      def self.ensure_values(key, values, error)
        proc do
          validate(error => key) do |array|
            if array.is_a?(Array)
              array.any? && array.select { |e| e.is_a?(Hash) }.all? do |h|
                (h.keys - values).empty?
              end
            else
              true
            end
          end
        end
      end
    end
  end
end
