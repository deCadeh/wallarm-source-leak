#

require 'wallarm/api'
require 'wallarm/common/processor'

class ExportSpotsProcessor < Processor
  def initialize( queue, config)
    super

    @queue = queue
    @wapi = Wallarm::API.new( config.api)

    @max_api_chunk = config.api_chunk
  end

  def process
    loop do
      spots = @queue.receive_spots( @max_api_chunk)
      break if spots.empty?

      @wapi.request( '/v1/objects/spot/create',
                     :state => 'detected',
                     :spots => spots)
      heartbeat
    end
  end
end
