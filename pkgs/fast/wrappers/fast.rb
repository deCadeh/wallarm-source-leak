module FastAPI
  module_function

  def reload
    @clientid      = nil
    @cloud_node_id = nil
    @node_id       = nil
  end

  def clientid
    @clientid ||= App.wapi.request(
      "/v1/user",
      {},
      format: :json,
      method: :post
    )['body']['clientid']
  end

  def node_id
    @node_id ||= App.wapi.request(
      "/v1/user",
      {},
      format: :json,
      method: :post
    )['body']['id']
    @node_id
  end

  def cloud_node_id
    @cloud_node_id ||= App.wapi.request(
      "/v1/user",
      {},
      format: :json,
      method: :post
    )['body']['cloud_node_id']
    @cloud_node_id
  end

  def lock_baseline_check(baseline_check_id)
    res = App.wapi.request(
      "/v1/baseline_check/#{baseline_check_id}/action/lock",
      { node_instance_id: node_id },
      method: :post, format: :json
    )
    true
  rescue => ex
    App.logger.error(ex)
    return false
  end

  def baseline_checks(test_run_id, limit, retry_timeout = 10)
    res1 = App.wapi.request(
      "/v1/baseline_check?limit=#{limit}&filter[test_run_id]=#{test_run_id}&filter[state][]=waiting",
      {},
      method: :get
    )['body']['objects']

    time_to = Time.now.to_i - retry_timeout

    res2 = App.wapi.request(
      "/v1/baseline_check?limit=#{limit}&filter[test_run_id]=#{test_run_id}&filter[state][]=retry&filter[status_changed_at][0][0]=0&filter[status_changed_at][0][1]=#{time_to}",
      {},
      method: :get
    )['body']['objects']

    (res1 + res2)[0...limit]
  end

  def test_runs(type = :node)
    continuation = nil
    test_runs    = []

    begin
      res = App.wapi.request(
        "/v1/test_run?order_desc=true&limit=100&filter[node_id]=#{cloud_node_id}&filter[type]=#{type}&clientid=#{clientid}&filter[state]=running&continuation=#{continuation}",
        {},
        method: :get
      )
      test_runs += res['body']['objects']

      continuation = res['body']['continuation']
    end while continuation
    test_runs
  end
end
