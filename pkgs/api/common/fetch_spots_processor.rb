#

require 'wallarm/common/processor'
require 'proton'
require 'proton/spots'

class FetchSpotsProcessor < Processor
  def initialize( queue, config)
    super

    @tdb = Tarantool16.new( config.tarantool)
    @queue = queue

    @max_queue_size = config.chunk_size * 10
  end

  def process
    loop do
      break if @queue.spots_queue_size > @max_queue_size

      firstid, count = @queue.receive_requests
      break if firstid.nil?

      tuples = @tdb.call( 'box.space.requests:select', [firstid, {limit: count}])

      if tuples != [[]]
        spots = []
        tuples.each do |t|
          begin
            req = Proton::SerializedRequest.new( t[1])
            spots += req.spots.map{ |s| { :tag => req.instance, :path => s } }
          rescue => e
            Log.error "Can't process spots for request #{t[0]} (#{e})"
          end
        end

        @queue.send_spots( spots)
      end

      @queue.last_processed_id = firstid + count - 1
      heartbeat
    end
  end
end
