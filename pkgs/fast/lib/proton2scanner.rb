require_relative './exclude'

module Proton2Scanner
  module_function

  def get_objects_from(req, point, preserve_auth = false, resolve_dns = true)
    unless [:uri, :header,:get,:post,:path,:action_name,:action_ext].include? point.point[0][0]
      App.logger.info 'Unsupported point'
      return []
    end

    if point.point[0]==[:header, 'HOST']
      App.logger.info 'We do not check HEADER_HOST_* points'
      return []
    end

    begin
      entry = req[point]
    rescue Proton::UnsupportedPointError => e
      App.logger.info 'Unsupported point'
      return []
    end

    if entry.nil?
      App.logger.error 'No such point in request'
      return []
    end

    req_to_raw = nil
    begin
      req_to_raw  = req.to_raw
    rescue => ex
      App.logger.error(ex)
      return []
    end

    http_method = req_to_raw[:method].to_s.downcase

    unless %w(
      get post put head options patch copy delete lock unlock move trace
    ).include? http_method
      App.logger.error 'Unsupported http method'
      return []
    end

    # Exclude sensitive params from request
    Exclude::web_money_lmi_hash(req)

    entry_value = entry.value.to_s
    if entry_value.to_i.to_s == entry_value
      entry_value_charset = :num
    else
      entry_value_charset = :alpha
    end

    res = []

    target = req.tags['attack_rechecker_target']
    if target
      App.logger.info 'Use attack_rechecker_target tag as server addr'

      uri = URI(target)

      object_params = {
        :point               => point,
        :entry               => entry,
        :port                => uri.port,
        :ip                  => uri.host,
        :preserve_auth       => preserve_auth,
        :req                 => req,
        :entry_value         => entry_value,
        :entry_value_charset => entry_value_charset
      }

      object = Wrappers::ScannerObject.new(object_params)

      res << object
    else
      req.ip_port(resolve_dns: resolve_dns).each do |ip, port|
        object_params = {
          :point               => point,
          :entry               => entry,
          :port                => port,
          :ip                  => ip,
          :preserve_auth       => preserve_auth,
          :req                 => req,
          :entry_value         => entry_value,
          :entry_value_charset => entry_value_charset
        }

        begin
          res << Wrappers::ScannerObject.new(object_params)
        rescue Wrappers::ScannerObject::ProtonError
          # Nothing to do
        end
      end
    end

    return res
  end

  def get_test_object(req, point)
    req   = IO.binread(req)
    req   = Proton::SerializedRequest.new(req)
    point = Proton::Point.new(point.str_decode)

    get_objects_from(req, point)[0]
  end
end

