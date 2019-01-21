require_relative './log_streamer/base_streamer'
require_relative './log_streamer/cache/redis'
require_relative './log_streamer/persistent_storage/es'

# Wallarm library for live msg streaming
module LogStreamer
  # Main LogStreamer class
  class Log
    attr_reader :cache, :persistent_storage

    def initialize(params = {})
      @wrappers = params[:wrappers] || {
        cache:              ->(block) { block.call },
        persistent_storage: ->(block) { block.call }
      }

      cache      = params.fetch(:cache)
      persistent = params.fetch(:persistent_storage)
      schema     = params.fetch(:schema)
      @id_schema = params.fetch(:id_schema)
      @cache_ttl = params.fetch(:cache_ttl)

      msg = 'Cache type is not :redis'
      raise ArgumentError, msg unless cache[:type] == :redis
      msg = 'PersistantStorage type is not :es'
      raise ArgumentError, msg unless persistent[:type] == :es

      cache[:cache_ttl] = @cache_ttl * 2
      cache[:schema] = schema
      persistent[:cache_ttl] = @cache_ttl
      persistent[:schema] = schema

      @cache = Cache::Redis.new(cache)
      @persistent_storage = PersistantStorage::ES.new(persistent)
    end

    def write(values)
      Thread.current[:log_streamer_id] ||= 0
      id = Thread.current[:log_streamer_id] += 1

      values = Marshal.load(Marshal.dump(values))
      values[:time] ||= Time.now.to_i
      values[:id]     = format(@id_schema, values.merge(id: id))

      @wrappers[:cache].call(-> { @cache.write(values) })
      @wrappers[:persistent_storage].call(-> { @persistent_storage.write(values) })
    end

    def check_connections
      @cache.check_connections
      @persistent_storage.check_connections
    end

    # returns [objects, continuation]
    def read(filter, opts = {})
      res = []

      opts[:limit] ||= 100

      first = opts[:continuation].nil?
      cont  = {}
      cont  = JSON.parse(opts[:continuation]) if opts[:continuation]

      cont['persistent'] ||= false

      query_persistent = false
      if (opts[:full] && !cont['full_requested']) || cont['persistent']
        query_persistent = true
      else
        ex = nil
        begin
          res = @cache.read(filter, cont['id'], cont['time'], opts[:limit])
        rescue => ex
        end
        cont['persistent'] = query_persistent = (res.empty? && first) || !ex.nil?
      end

      if query_persistent
        res, inconsistency = @persistent_storage.read(
          filter, cont['id'] || '', cont['time'] || 0, opts[:limit]
        )
        cont['persistent'] = !inconsistency
      end

      cont['full_requested'] = true if opts[:full]

      fill_cont(res, cont)

      [res[0...opts[:limit]], cont.to_json]
    end

    private

    def fill_cont(res, cont)
      return if res.empty?
      cont['id']   = res.last['id']
      cont['time'] = res.last['time']
    end
  end
end
