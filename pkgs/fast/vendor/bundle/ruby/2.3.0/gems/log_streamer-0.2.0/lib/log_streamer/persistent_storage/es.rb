require_relative './es_orm/es_orm'
require 'elasticsearch'

module LogStreamer
  module PersistantStorage
    # PersistantStorage ES implementation
    class ES < BaseStreamer
      attr_reader :elasticsearch

      def check_connections
        @elasticsearch.ping
      end

      def initialize(params)
        @schema = Marshal.load(Marshal.dump(params[:schema]))
        @schema[:id] = :string
        @schema[:time] = :time_interval

        schema      = @schema
        date_schema = params[:date_schema]
        step        = params[:date_step]
        @klass = Class.new(EsOrm) do
          es_type :log_record

          schema.each do |k, v|
            es_field k, type: v
            es_filter_by k
          end

          es_process :id, ->(k, v) { [gt(k, v)] }

          es_time_format date_schema

          es_default_time_processer(name: :time, step: step)
        end

        es_params = {
          hosts: params[:addrs],
          transport_options: {
            request: {
              timeout:      30,
              open_timeout: 30
            }
          },
          retry_on_failure: true
        }

        @elasticsearch ||= Elasticsearch::Client.new(es_params)
        @klass.set_connection(@elasticsearch)

        super params
      end

      def write(values)
        @klass.create(values)
      end

      def read(filter, last_id, _last_time, limit)
        time = Time.now.to_i
        all  = []

        if last_id
          filter = filter.merge(id: last_id) if last_id != ''
          all = @klass.filter(filter).limit(limit).order_by(:id, :asc).all.map(&:to_h)
        else
          all = @klass.filter(filter).limit(limit).order_by(:id, :desc).all.map(&:to_h).reverse
        end

        res = []
        inconsistency = false
        all.each do |record|
          if record['time'] > time - @params[:cache_ttl]
            inconsistency = true
            break
          end
          res << record
        end

        inconsistency = true if res.empty?

        [res, inconsistency]
      end
    end
  end
end
