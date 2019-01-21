require 'wallarm/api'
require 'wallarm/common/processor'

class ExportAttacksProcessor < Processor
  def initialize( queue, config)
    super

    @queue = queue
    @api_chunk = config.api_chunk || 10

    @wapi = Wallarm::API.new( config.api)
  end

  def process
    loop do
      tuples = @queue.receive_for_export( @api_chunk)
      hits = tuples.map{ |t| t[1] }
      ids = tuples.map{ |t| t[0] }

      break if tuples.empty?

      heartbeat

      Log.info "#{@name}: exporting #{ids.count} requests"
      @wapi.request( '/v1/objects/hit/create', :hits => hits)
      @queue.ack_export( ids)
      Log.info "#{@name}: exported #{ids.count} requests"
    end
  end
end
