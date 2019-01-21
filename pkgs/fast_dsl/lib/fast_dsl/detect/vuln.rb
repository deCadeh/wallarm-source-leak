module FastDsl
  class Detect
    # if detect finds trigers we add vuln to context
    class Vuln
      attr_accessor(
        :type, # sync, async
        :trigger_name,
        :payload_check,
        :payload,
        :insertion_point_value,
        :marker,
        :exploit_stamp,
        :oob_triggered_ip
      )

      def initialize(opts)
        opts.each { |k, v| send("#{k}=", v) }
      end
    end
  end
end
