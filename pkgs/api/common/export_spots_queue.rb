require 'wallarm/common/processor'

class ExportSpotsQueue
  attr_reader :last_processed_id

  def initialize
    @mutex = Mutex.new
    @requests_queue = []
    @requests_count = 0
    @spots_queue = []
  end

  def set_range( firstid, lastid)
    if firstid.nil? or lastid.nil?
      @mutex.synchronize do
        @requests_count = 0
        @requests_queue = []
      end
    else
      first_ids = (firstid..lastid).step(100).to_a
      counts = first_ids.map{ |id| [lastid - id + 1, 100].min }

      @mutex.synchronize do
        @requests_count = lastid - firstid + 1
        @requests_queue = first_ids.zip(counts)
      end
    end

    true
  end

  def processed
    return 0 if @requests_count == 0

    count = @requests_queue.inject(0.0){ |s,e| s + e[1] }
    count / @requests_count
  end

  def receive_requests
    @mutex.synchronize do
      @requests_queue.shift
    end
  end

  def last_processed_id=( id)
    @last_processed_id = [ @last_processed_id.to_i, id].max
  end

  def send_spots( spots)
    @mutex.synchronize do
      @spots_queue += spots
      @spots_queue.uniq!
    end
    nil
  end

  def receive_spots( count)
    @mutex.synchronize do
      @spots_queue.shift( count)
    end
  end

  def spots_queue_size
    @spots_queue.size
  end
end
