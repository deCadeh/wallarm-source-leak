module BaselineCheckAPI
  module_function

  def test_run(id)
    App.wapi.request(
      "/v1/test_run/#{id}",
      {},
      format: :json,
      method: :get
    )['body']
  end

  def apply_test_policy(id)
    App.wapi.request(
      "/v1/test_policy/#{id}/action/apply",
      {},
      format: :json,
      method: :post
    )
  end

  def test_policy_by_name(name, clientid)
    App.wapi.request(
      "/v1/test_policy?clientid=#{clientid}&filter[name]=#{CGI::escape(name)}",
      {},
      format: :json,
      method: :get
    )['body']['objects'][0]
  end

  def update_counters(id, requests_count, checks_count)
    App.wapi.request(
      "/v1/baseline_check/#{id}/counters",
      { finished_checks_count: checks_count, sended_requests_count: requests_count },
      format: :json,
      method: :put
    )
  end

  def set_total_checks_count(id, count)
    App.wapi.request(
      "/v1/baseline_check/#{id}/counters",
      { total_checks_count: count },
      format: :json
    )
  end

  def run(args)
    App.wapi.request("/v1/baseline_check/#{args[:id]}/action/run", {}, format: :json)
  rescue Wallarm::API::BadRequest
    false
  end

  def add_vuln(args)
    App.wapi.request("/v1/baseline_check/#{args[:id]}/action/vuln", args, format: :json)
  rescue Wallarm::API::BadRequest
    false
  end

  def silent_retry(args)
    App.wapi.request("/v1/baseline_check/#{args[:id]}/action/silent_retry", {}, format: :json)
  rescue Wallarm::API::BadRequest
    false
  end

  def retry(args)
    App.wapi.request("/v1/baseline_check/#{args[:id]}/action/retry", {}, format: :json)
  rescue Wallarm::API::BadRequest
    false
  end

  def tech_fail(args)
    App.wapi.request("/v1/baseline_check/#{args[:id]}/action/tech_fail", { reason: args[:reason] }, format: :json)
  rescue Wallarm::API::BadRequest
    false
  end

  def failed(args)
    App.wapi.request("/v1/baseline_check/#{args[:id]}/action/fail", args, format: :json)
  rescue Wallarm::API::BadRequest
    false
  end

  def passed(args)
    App.wapi.request("/v1/baseline_check/#{args[:id]}/action/pass", { reason: args[:reason] }, format: :json)
  rescue Wallarm::API::BadRequest
    false
  end

  def create_record(args)
    App.wapi.request(
      "/v1/baseline_check/#{args[:baseline_check_id]}/record",
      args.select { |arg| %i[level msg].include? arg },
      format: :json,
      method: :post
    )
  end
end
