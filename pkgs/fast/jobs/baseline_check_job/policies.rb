class BaselineCheckJob
  # Extend BaselineCheckJob to handle policies
  module PoliciesHelper
    def default_policy
      {
        type_include:      %i[xss sqli ptrav rce],
        type_exclude:      [],
        parameter_include: [/\AGET/, /\APOST/],
        parameter_exclude: []
      }
    end

    def compile_regexp(str)
      Regexp.new(str.delete("'"))
    rescue
      raise ScannerExtensions::Helpers::FuzzerConditions::InvalidPolicies
    end

    def parse_insertion(values, cur_policy)
      opts = {
        'include' => [],
        'exclude' => []
      }
      last_opt_name = nil
      values.each do |item|
        opt_name, opt = item.split(':')
        if opt_name && opt
          opts[opt_name] = [opt]
          last_opt_name = opt_name
        elsif last_opt_name
          opts[last_opt_name] += [opt_name]
        else
          raise ScannerExtensions::Helpers::FuzzerConditions::InvalidPolicies
        end
      end
      cur_policy[:parameter_include] = opts['include'].map do |point|
        compile_regexp(point)
      end.compact
      cur_policy[:parameter_exclude] = opts['exclude'].map do |point|
        compile_regexp(point)
      end.compact
    end

    def parse_policies(req, test_run_id = nil)
      result = []

      allowed_extension_types = %i[xss xxe sqli rce ptrav fuzzer]

      ObjectHelpers.parse_policies(req, test_run_id).each do |policies|
        cur_policy       = Marshal.load(Marshal.dump(default_policy))
        cur_policy[:raw] = policies

        policies.each do |policy|
          name, values = policy
          case name
          when 'insertion'
            parse_insertion(values, cur_policy)
          when 'type'
            positive = values.reject { |v| v[0] == '!' }.map(&:to_sym)
            negative = values.select { |v| v[0] == '!' }.map { |v| v[1..-1] }.map(&:to_sym)

            selector = proc do |type|
              allowed_extension_types.include?(type)
            end

            cur_policy[:type_include] = positive.select(&selector)

            if !positive.reject(&selector).empty? && positive != [:all]
              raise ScannerExtensions::Helpers::FuzzerConditions::InvalidPolicies
            end

            cur_policy[:type_exclude] = negative.select(&selector)

            unless negative.reject(&selector).empty?
              raise ScannerExtensions::Helpers::FuzzerConditions::InvalidPolicies
            end

            cur_policy[:type_include] = allowed_extension_types if values.include?('all')

            cur_policy[:type_exclude].uniq!
            cur_policy[:type_include].uniq!
          end
        end

        result << cur_policy
      end

      result
    end
  end
end
