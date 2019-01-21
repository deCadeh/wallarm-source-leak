require 'app'

# module for promitheus
module Metric
  module_function

  def es_status
    return @hs if @hs
    @hs = {}
    Elasticsearch::Transport::Transport::HTTP_STATUSES.each_pair { |key, value| @hs[value] = key }
  end

  def elastic_log(block)
    metric_name = 'testrun_rechecker_elastic_log_time_seconds'
    start = Time.now.to_i

    block.call

    App.statsd.timing(metric_name, Time.now.to_i - start, tags: ['status:200'])
  rescue Elasticsearch::Transport::Transport::ServerError => ex
    name_response = ex.class.name.split('::')[-1]
    App.statsd.timing(metric_name, Time.now.to_i - start, tags: ["status:#{es_status[name_response]}"])
    raise ex
  rescue => ex
    App.statsd.timing(metric_name, Time.now.to_i - start, tags: ['status:0'])
    raise ex
  end

  def redis_log(block)
    metric_name = 'testrun_rechecker_redis_log_time_seconds'
    start = Time.now.to_i

    block.call

    App.statsd.timing(metric_name, Time.now.to_i - start, tags: ['result:success'])
  rescue => ex
    App.statsd.timing(metric_name, Time.now.to_i - start, tags: ['result:fail'])
    # supress redis exception
    App.logger.error(ex)
  end
end
