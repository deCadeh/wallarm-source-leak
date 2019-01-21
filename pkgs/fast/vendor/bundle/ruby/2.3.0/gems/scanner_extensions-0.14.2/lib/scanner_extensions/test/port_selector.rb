module ScannerExtensions
  module Test
    module PortSelector
      def get_open_port
        @@port ||= 9020
        @@port  += 1
      end
    end
  end
end
