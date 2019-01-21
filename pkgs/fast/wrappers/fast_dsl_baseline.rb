module Wrappers
  module FastDslBaseline
    def request(params)
      http(params.merge(timeout: 10, open_timeout: 10))
    end

    def each_point_value
      @params[:req].each do |entry|
        point = entry.point.to_s.normalize_enconding
        value = entry.value.normalize_enconding
        yield point, value
      end
    end

    def insertion_point_value
      @params[:entry_value].normalize_enconding
    end

    def set_point_value(point, value)
      req   = @params[:req]
      entry = req[Proton::Point.new(point)]
      return unless entry
      entry.value = value
    rescue => ex
      App.logger.error(ex)
    end

    def insertion_point
      @params[:entry].point.to_s.normalize_enconding
    end
  end
end
