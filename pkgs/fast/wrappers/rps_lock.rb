require 'rps_limit'

class RpsLock
  attr_reader :rps

  def self.lock(test_run_id)
    res = App.wapi.request(
      '/v1/rps_lock',
      { test_run_id: test_run_id },
      format: :json,
      method: :post
    )
    res['body']['secret'] ? self.new(res['body']) : RpsLimit::SessionLock.new(res['body']['rps'])
  rescue Wallarm::API::BadRequest
    return nil
  end

  def initialize(params)
    @rps    = params['rps']
    @secret = params['secret']
  end

  def rpm
    @rps * 60
  end

  def unlock
    App.wapi.request(
      '/v1/rps_lock',
      { secret: @secret },
      format: :json,
      method: :delete
    )
  end

  def heartbeat
    App.wapi.request(
      '/v1/rps_lock',
      { secret: @secret },
      format: :json,
      method: :put
    )
  end
end
