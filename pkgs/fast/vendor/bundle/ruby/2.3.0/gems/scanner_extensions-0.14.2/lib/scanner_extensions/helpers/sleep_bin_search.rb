module ScannerExtensions
  module Helpers
    module SleepBinSearch
      module_function

      def cmp_times(t1, t2, delta)
        max = [t1, t2].max.to_f
        min = [t1, t2].min.to_f
        max = 1.0 if max == 0
        min = 1.0 if min == 0
        (1.0 - min / max < delta)
      end

      def preform(params)
        params = {
          start_time: 0.001,
          step_mul: 4,
          reliable: 4,
          max: 18,
          delta: 0.30,
          coeff: 1.6,
          start: 16.1
        }.merge(params)
        delta    = params[:delta]
        start    = params[:start]
        max      = params[:max]
        reliable = params[:reliable]
        coeff    = params[:coeff]
        base     = params[:f].call(0, max, params[:f_args])
        return nil unless base
        test = params[:f].call(start, start.to_i, params[:f_args])
        if test
          return nil if test < start.to_i
        end
        time = params[:start_time]
        loop do
          cur = params[:f].call(time, max, params[:f_args])
          return nil unless cur
          return nil if cur < time
          cur -= base
          if cur > reliable
            round = (time * coeff * 100_000).to_i.to_f / 100_000
            stat2 = params[:f].call(round, max, params[:f_args])
            return nil unless stat2
            return nil if stat2 + 0.1 < round

            stat2 -= base

            return nil if stat2 < 0
            return nil if cur   < 0
            return nil if stat2 < cur

            if cmp_times(stat2, cur * coeff, delta)
              test = params[:f].call(0, max, params[:f_args])
              return nil unless cmp_times(test + 2, base + 2, delta)
              return {
                sleep_arg1: time,
                time1: cur + base,
                sleep_arg2: round,
                time2: stat2 + base
              }
            end
            return nil
          end
          break if time > params[:reliable]
          time *= params[:step_mul]
        end
        nil
      end
    end
  end
end
