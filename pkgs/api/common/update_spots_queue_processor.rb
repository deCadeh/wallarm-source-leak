#

require 'tarantool16'
require 'wallarm/common/processor'

class UpdateSpotsQueueProcessor < Processor
  def initialize( queue, config)
    super

    @min_delay = 60
    @queue = queue

    @tdb = Tarantool16.new( config.tarantool)

    @iteration_time = config.iteration_time
    @max_iterations = config.max_iterations
  end

  def process
    Log.info("Processed %.3f%% spots" % @queue.processed)
    @tdb.call( 'wallarm.mark_processed_spots', [@queue.last_processed_id]) unless @queue.last_processed_id.nil?

    firstid, lastid = unprocessed_requests
    @queue.set_range( firstid, lastid)
  end

  def unprocessed_requests
    first, last = @tdb.call( "wallarm.unprocessed_spots", [])

    return if first.nil? or last.nil?

    firstid   = first[0]
    firsttime = first[1]
    lastid    = last[0]
    lasttime  = last[1]

    total = lastid+1-firstid
    time = lasttime+1-firsttime

    if time > @iteration_time * @max_iterations
      k = 1.0 / @max_iterations
      lastid = firstid + (k*total).to_i
    elsif time > @iteration_time
      k = 1.0 * @iteration_time / time
      lastid = firstid + (k*total).to_i
    end

    Log.info "#{lastid+1-firstid}/#{total} requests for process"

    [firstid, lastid]
  end
end
