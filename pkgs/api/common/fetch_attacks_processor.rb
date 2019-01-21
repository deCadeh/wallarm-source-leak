require 'tarantool16'
require 'wallarm/common/processor'

class FetchAttacksProcessor < Processor
  def initialize( queue, config)
    super

    @queue = queue

    @min_probability_for_type0 = config.min_probability_for_type0
    @max_tuples = config.tarantool_chunk
    @min_queue_size = config.tarantool_chunk / 2

    @tdb = Tarantool16.new(
      :host => config.tarantool.host,
      :port => config.tarantool.port)
  end

  private

  def process
    while !@stop and @queue.export_queue_size < @min_queue_size
      tuples = @tdb.call( "wallarm.unprocessed_attacks",
                          [ @min_probability_for_type0, @max_tuples])

      break if tuples.empty?

      count = @queue.send( tuples.map{ |t| [t[0], t[1]] })

      heartbeat

      break if count == 0 
    end
  end
end
