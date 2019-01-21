# Helpers to run extensions for ValidatorJobs and BaselineCheckJob
module ObjectHelpers
  module_function

  def parse_policies(req, test_run_id = nil)
    headers = []

    test_run = BaselineCheckAPI.test_run(test_run_id)
    clientid = test_run['clientid']

    if req.to_raw && req.to_raw[:headers] && req.to_raw[:headers]['X-WALLARM-TEST-POLICY']
      headers = req.to_raw[:headers]['X-WALLARM-TEST-POLICY']
    else
      if test_run['policy_name']
        headers = [test_run['policy_name']]
      else
        return [[]]
      end
    end

    result = []

    headers.each do |header|
      # policy is set by name
      unless header.index('=')
        test_policy_name = header
        test_policy      = BaselineCheckAPI.test_policy_by_name(
          test_policy_name,
          clientid
        )
        unless test_policy
          msg = "TestPolicy with name '#{test_policy_name}' does not exist"
          App.log(level: :error, msg: msg)
          raise ScannerExtensions::Helpers::FuzzerConditions::InvalidPolicies
        end

        BaselineCheckAPI.apply_test_policy(test_policy['id'])

        header = test_policy['header']
        header = header.gsub(/\AX-Wallarm-Test-Policy:/, '')

        msg = "Use TestPolicy with name '#{test_policy_name}'"
        App.log(level: :info, msg: msg)
      end
      cur_policy = []
      parts = header.split(';')
      parts.each do |part|
        # skip spaces not in quotes
        part.gsub!(/\s+(?=([^']*'[^']*')*[^']*$)/, '')
        # do not split >= & <=
        name, values = part.split(/(?<![<>])=/)
        next unless name && values
        values = values.split(',').map { |str| str.delete("'") }
        cur_policy << [name, values]
      end
      result << cur_policy
    end

    result
  end

  def get_policy_values_by_type(policy, type)
    result = []
    policy.each do |item|
      name, values = item
      next unless name == type
      result += values
    end
    result
  end

  def check_connection(object, log = false)
    object.params[:info][:extension] = 'CheckConnectionWithServer'

    # Do we need to use SSL or not?
    use_ssl = []

    object.params[:use_ssl] = false
    resp = object.http(value: object.params[:entry_value], open_timeout: 10, timeout: 10)
    http_ok   = resp ? resp.code.to_i != 400 : false
    http_resp = resp
    if log
      if resp
        msg = "Connection OK #{object.desc}"
        App.log(level: :info, msg: msg)
      else
        msg = "Connection FAIL #{object.desc}"
        App.log(level: :info, msg: msg)
      end
    end

    object.params[:use_ssl] = true
    resp = object.http(value: object.params[:entry_value], open_timeout: 10, timeout: 10)
    https_ok   = resp ? resp.code.to_i != 400 : false
    https_resp = resp
    if log
      if resp
        msg = "Connection OK #{object.desc}"
        App.log(level: :info, msg: msg)
      else
        msg = "Connection FAIL #{object.desc}"
        App.log(level: :info, msg: msg)
      end
    end

    return [] if !https_resp && !http_resp

    if https_ok ^ http_ok
      use_ssl << https_ok
    else
      use_ssl = [true, false]
    end

    use_ssl
  end

  def get_extensions(detect_type, point, type = :rechecker)
    extensions = ScannerExtensions::Loader.extensions_by_detect_type(
      detect_type,
      fast: type == :fast
    ).select do |ext|
      ext.point ? ext.point.call(point) : true
    end

    extensions = [CustomExtensions.custom_extension] if detect_type == :custom

    extensions.select do |ext|
      name = ext.class.to_s.split('::').last
      enabled = true
      if App.config.extensions
        if App.config.extensions[name]
          enabled = false if App.config.extensions[name][:disabled] == true
        end
      end
      enabled
    end
  end
end
