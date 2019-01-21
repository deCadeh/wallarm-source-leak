# tuples states
#   1. queued for export
#   2. exporting
#   3. queued for mark exported
#   4. marking exported
#

class ExportAttacksQueue
  def initialize
    @mutex = Mutex.new
    @wait_export_queue = []
    @process_export_queue = []
    @wait_mark_queue = []
    @process_mark_queue = []
    @history = []
  end

  def receive_for_export( count)
    messages = []

    @mutex.synchronize do
      time = Time.now.to_i
      messages = @wait_export_queue.shift(count)
      @process_export_queue += messages.map{ |m| [time, m[0], m[1]] }
    end

    Log.debug { "ExportQueue#receive_for_export: #{messages.map{ |m| m[0] }.join(',')}" } unless messages.empty?

    messages
  end

  def fail_export( ids)
    @mutex.synchronize do
      @process_export_queue.reject!{ |m| ids.include? m[1] }
    end
  end

  def ack_export( ids)
    a = []

    @mutex.synchronize do
      a,b = @process_export_queue.partition{ |m| ids.include? m[1] }
      @process_export_queue = b
      @wait_mark_queue += a.map{ |m| m[1] }
    end

    Log.debug { "ExportQueue#ack_export: #{a.map{ |m| m[1] }.join(',')}" } unless a.nil?

    nil
  end

  def receive_for_mark( count)
    messages = []

    @mutex.synchronize do
      time = Time.now.to_i
      messages = @wait_mark_queue.shift(count)
      @process_mark_queue += messages.map{ |m| [time, m] }
    end

    Log.debug { "ExportQueue#receive_for_mark: #{messages.join(',')}" } unless messages.empty?

    messages
  end

  def ack_mark( ids)
    a = []

    @mutex.synchronize do
      a,b = @process_mark_queue.partition{ |m| ids.include? m[1] }
      @process_mark_queue = b
      @history += a
      delete = @history.count - 1000
      @history.shift(delete) if delete > 0
    end

    Log.info( "#{a.count} requests marked as exported") unless a.empty?
    Log.debug { "ExportQueue#ack_mark: #{a.map{ |m| m[1] }.join(',')}" } unless a.empty?

    nil
  end

  # accept array of [id, sreq] tuples
  def send( messages)
    count = 0

    Log.debug { "ExportQueue#send: #{messages.map{ |m| m[0] }.join(',')}" }

    @mutex.synchronize do
      ids  = @wait_export_queue.map{ |m| m[0] }
      ids += @process_export_queue.map{ |m| m[1] }
      ids += @wait_mark_queue
      ids += @process_mark_queue.map{ |m| m[1] }
      ids += @history.map { |m| m[1] }
      messages.each do |msg|
        next if ids.include? msg[0]
        @wait_export_queue << msg
        count += 1
      end
    end

    Log.info( "#{count} requests added to export queue") unless count == 0

    count
  end

  def handle_stalled
    time = Time.now.to_i - 120
    a = []
    b = []

    @mutex.synchronize do
      a,b = @process_export_queue.partition{ |m| m[0] < time }
      @process_export_queue = b
    end

    Log.debug { "ExportQueue#handle_stalled: remove from export queue #{a.map{ |m| m[1] }.join(',')}" } unless a.empty?

    @mutex.synchronize do
      a,b = @process_mark_queue.partition{ |m| m[0] < time }
      @process_mark_queue = b
      @wait_mark_queue += b.map{ |m| m[1] }
    end

    Log.debug { "ExportQueue#handle_stalled: return to mark queue #{b.map{ |m| m[1] }.join(',')}" } unless b.empty?

    true
  end

  def export_queue_size
    @mutex.synchronize do
      @wait_export_queue.size + @process_export_queue.size
    end
  end

  def empty?
    @mutex.synchronize do
      @wait_export_queue.empty? \
        and @process_export_queue.empty? \
        and @wait_mark_queue.empty? \
        and @process_mark_queue.empty?
    end
  end
end
