module ScannerExtensions
  module Helpers
    module UnionBytes
      module_function

      def format(bytes)
        res   = []
        prev  = nil
        start = nil

        (bytes.sort + [nil]).each do |e|
          if prev.nil?
            start = e
            prev  = e
          else
            if prev + 1 != e
              res << if prev == start
                       prev
                     else
                       [start, prev]
                     end
              prev  = e
              start = e
            else
              prev = e
            end
          end
        end

        res.map do |e|
          if e.is_a?(Array)
            f = Kernel.format('0x%02X', e[0])
            s = Kernel.format('0x%02X', e[1])
            f + '-' + s
          else
            Kernel.format('0x%02X', e)
          end
        end.join(', ')
      end
    end
  end
end
