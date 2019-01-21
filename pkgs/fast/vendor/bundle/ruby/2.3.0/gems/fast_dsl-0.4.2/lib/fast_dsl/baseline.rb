module FastDsl
  # just stuipid abstract interface implementation
  module Baseline
    module_function

    def all_methods_implemented?(klass)
      %i[request each_point_value set_point_value insertion_point insertion_point_value].each do |name|
        raise "Method #{name} is required" unless klass.instance_methods(false).include?(name)
      end
    end
  end
end
