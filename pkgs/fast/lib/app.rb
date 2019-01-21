require 'general_job'
require 'hashie/mash'
require 'qless'
require 'log_streamer'
require 'scanner_extensions'
require 'wallarm_logger'
require 'datadog/statsd'
require_relative './metric'
require_relative './log_formatter'
require_relative './remote_logger'

# Preserve formatter
class StandartLogger < Logger
  def reopen
    close unless params[0] == STDOUT
    r = StandartLogger.new *params
    r.formatter = formatter
    r
  end
end

# Support jid logging
class LoggerHub
  def jid=(val)
    @loggers.each { |logger| logger.formatter.jid = val }
  end
end

ActiveLoggerHubs.trap('SIGWINCH')

module App
  class << self
    def config
      @config ||= Hashie::Mash.new(
        api: Wallarm::API::DEFAULTS.merge(
          ca_verify: false
        ),
        log_file: STDOUT,
        redis: 'redis://127.0.0.1/0',
        queue: 'scanner',
        # save_attack_status_redis: 'redis://127.0.0.1/0',
        # save_attack_status_queue: 'save_attack_status',
        private_scan: false,
        max_requests: 1000,
        max_memory: 2**27,
        extensions: {},
        wait_validated_timeout: 30,
        log_streamer: {
          cache_ttl: 10,
          redis_addr: 'redis://127.0.0.1/0',
          elastic_schema: '%Y%m%d',
          elastic_step: 86_400,
          elastic_addrs: '127.0.0.1:9200;127.0.0.2:9200'
        },
        #:rps_limit => {
        #  :port    => 2379
        # },
        exceptions: [
          [/BaselineCheckJob/,         { action: :retry, tries: 3, timeout: 5 * 60 }],
          [/BaselineCheckError/,       { action: :retry, tries: 5, timeout: 5 * 60 }],
          [/RpsLimit::EtcdError/,      { action: :retry, tries: 5, timeout: 30 * 60 }],
          [/OpenSSL::SSL::SSLError/,   { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/Timeout::Error/,           { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/Errno::ECONNREFUSED/,      { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/Errno::EHOSTUNREACH/,      { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/SocketError/,              { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/EOFError/,                 { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/Errno::ECONNRESET/,        { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/Net::HTTPFatalError/,      { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/Net::OpenTimeout/,         { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/Net::ReadTimeout/,         { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/API::ServerError/,         { action: :retry, tries: 5, timeout: 10 * 60 }],
          [/API::InternalServerError/, { action: :retry, tries: 5, timeout: 10 * 60 }]
        ],
        remote_logger: {
          retry_timeout: 5
        }
      )
    end

    def init
      RpsLimit.config = config.rps_limit if config.rps_limit
    end

    def log_streamer
      @log_streamer ||= LogStreamer::Log.new(
        wrappers: {
          cache:              Metric.method(:redis_log),
          persistent_storage: Metric.method(:elastic_log)
        },
        id_schema: '%0<time>10i:%0<id>10i',
        schema: {
          baseline_check_id: :int,
          msg:               :string,
          level:             :string
        },
        cache_ttl: config.log_streamer.cache_ttl,
        cache: {
          type: :redis,
          key_schema: '%<baseline_check_id>i',
          addr: config.log_streamer.redis_addr
        },
        persistent_storage: {
          type: :es,
          date_schema: config.log_streamer.elastic_schema,
          date_step: config.log_streamer.elastic_step,
          addrs: config.log_streamer.elastic_addrs.split(';')
        }
      )
    end

    def switch_to_http_logger
      def App.log_streamer
        if @remote_logger.nil?
          @remote_logger = RemoteLogger.new
          @remote_logger.run!
        end

        @remote_logger
      end
    end

    def log(params)
      App.logger.send(params[:level], params[:msg])

      params = params.merge(
        baseline_check_id: Thread.current[:baseline_check_id]
      )

      begin
        log_streamer.write(params)
      rescue => ex
        App.logger.error(ex)
      end
    end

    def statsd
      statsd_host = ENV.fetch('STATSD_HOST', '127.0.0.1')
      statsd_port = ENV.fetch('STATSD_PORT', 9125).to_i
      @statsd ||= Datadog::Statsd.new(statsd_host, statsd_port)
    end

    def wapi
      @wapi ||= Wallarm::API.new(config.api)
    end

    def wapi=(config)
      @wapi = Wallarm::API.new(config)
    end

    def watch_node_yaml
      node_yaml = IO.binread('/etc/wallarm/node.yaml')
      return if node_yaml == @node_yaml
      @node_yaml = node_yaml
      config = YAML.load(@node_yaml)
      App.config.api = {
        uuid:      config['uuid'],
        secret:    config['secret'],
        host:      ENV.fetch('WALLARM_API_HOST', 'api.wallarm.com'),
        port:      ENV.fetch('WALLARM_API_PORT', '443'),
        use_ssl:   ENV.fetch('WALLARM_API_USE_SSL', 'true').casecmp('true').zero?,
        ca_verify: ENV.fetch('WALLARM_API_CA_VERIFY', 'false').casecmp('true').zero?
      }
      App.wapi = App.config.api
      FastAPI.reload
    end

    def queue
      @queue ||= Qless::Client.new(url: config.redis, tcp_keepalive: 5).queues[config.queue]
    end

    def save_attack_status_queue
      @attack_status_queue ||= Qless::Client.new(url: config.save_attack_status_redis, tcp_keepalive: 5)
                                            .queues[config.save_attack_status_queue]
    end

    def logger
      if @logger.nil?
        logger = StandartLogger.new(config.log_file)
        logger.formatter = LogFormatter.new
        @logger = LoggerHub.new
        @logger.add_logger(logger)
      end
      @logger
    end
  end
end

require './lib/exceptions'
