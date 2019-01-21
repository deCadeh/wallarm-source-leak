require 'tarantool16'
require 'wallarm/common/processor'

class MarkAttacksProcessor < Processor
  def initialize( queue, config)
    super

    @queue = queue
    @max_ids_for_mark = config.tarantool_chunk

    @tdb = Tarantool16.new(
      :host => config.tarantool.host,
      :port => config.tarantool.port)
  end

  private

  def process
    loop do
      ids = @queue.receive_for_mark(@max_ids_for_mark)
      break if ids.empty?

      @tdb.call( "wallarm.mark_processed_attacks", ids)
      @queue.ack_mark( ids)

      heartbeat

      break if ids.count < @max_ids_for_mark
    end
  end
end
