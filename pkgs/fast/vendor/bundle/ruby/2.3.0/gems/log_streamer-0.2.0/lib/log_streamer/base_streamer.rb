require 'json'

module LogStreamer
  # Generate ids
  class BaseStreamer
    def initialize(params)
      @params = params
    end

    def key_schema(values)
      @params[:key_schema] && 'log_streamer:' + format(@params[:key_schema], values)
    end

    def date_schema(values)
      @params[:date_schema] && Time.at(values[:time]).strftime(@params[:date_schema])
    end
  end
end
