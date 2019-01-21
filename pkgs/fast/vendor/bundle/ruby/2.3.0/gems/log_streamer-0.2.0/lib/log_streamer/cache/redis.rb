require 'redis'

module LogStreamer
  module Cache
    # Cache Redis implementation
    class Redis < BaseStreamer
      def initialize(params)
        @redis = ::Redis.new url: params[:addr]
        super params
      end

      def check_connections
        @redis.info
      end

      def write(values)
        key = key_schema(values)
        @redis.zadd(key, values[:time], marshal(values))
        @redis.expire(key, @params[:cache_ttl])
        @redis.zremrangebyscore(key, '-inf', Time.now.to_i - @params[:cache_ttl] - 1)
      end

      def read(filter, last_id, last_time, limit)
        key = key_schema(filter)

        # return last <limit> records if continuation is not provided
        return @redis.zrange(key, -limit, -1).map { |r| unmarshal(r) } unless last_time

        # should get all records of same time
        same_time_records = @redis.zrangebyscore(key, last_time, last_time)
        # and just next <limit> records
        next_time_records = @redis.zrangebyscore(key, last_time + 1, '+inf', limit: [0, limit])

        all_records = (same_time_records + next_time_records).map { |r| unmarshal(r) }

        res = []
        found = false
        all_records.each do |record|
          if record['id'] == last_id
            found = true
          else
            next unless found
            res << record
          end
        end
        # if something goes wrong
        res = all_records unless found
        res[0...limit]
      end

      private

      def marshal(values)
        values[:id] + '@' + values.to_json
      end

      def unmarshal(str)
        JSON.parse(str.split('@', 2)[1])
      end
    end
  end
end
