# -*- encoding: utf-8 -*-
require 'resolv-replace'
require 'erb'
require 'vuln_templates'
require 'cgi'

require './wrappers/baseline_check_api'

require_relative './wapi'

module WapiMixins
  def req_by_es_hit_id(es_hit_id)
    Timeout::timeout(15) do
      data = request('/v1/objects/hit/raw', :filter => {:id => es_hit_id})
      Proton::SerializedRequest.new(data)
    end
  rescue Timeout::Error
    msg = "Unable to access /v1/objects/hit/raw for hit ##{es_hit_id}}"
    App.logger.error(msg)
    return nil
  rescue => ex
    App.logger.error(ex)
    return nil
  end

  def req_without_token(path, params, opt)
    token  = @token
    @token = nil
    request(path, params, opt)
  ensure
    @token = token
  end

  def vuln_found(attack_id, vulnid)
    hash = {
      :attackid    => attack_id[0],
      :attackindex => attack_id[1],
      :vulnid      => vulnid
    }
    req_without_token('/v1/rechecker/vuln_found', hash, format: :json)
  rescue Wallarm::API::BadRequest, Wallarm::API::NotFound => ex
    App.logger.error(ex)
  end

  def vuln_not_found(attack_id)
    hash = {
      :attackid    => attack_id[0],
      :attackindex => attack_id[1]
    }
    req_without_token('/v1/rechecker/vuln_not_found', hash, format: :json)
  rescue Wallarm::API::BadRequest, Wallarm::API::NotFound => ex
    App.logger.error(ex)
  end

  def tech_failed(attack_id)
    hash = {
      :attackid    => attack_id[0],
      :attackindex => attack_id[1]
    }
    req_without_token('/v1/rechecker/tech_failed', hash, format: :json)
  rescue Wallarm::API::BadRequest, Wallarm::API::NotFound => ex
    App.logger.error(ex)
  end

  def vuln_by_id(vuln_id)
    hash = { filter: { id: vuln_id.to_i } }
    res  = request('/v1/objects/vuln', hash)

    res['body'][0]
  end

  def get_vuln(vuln_id)
    hash = {
      :filter => {
        :id => vuln_id.to_i
      }
    }
    res = request('/v1/objects/vuln', hash)
    clientid = res['body'][0]['clientid']          rescue nil
    vuln_rd  = res['body'][0]['vuln_recheck_data'] rescue nil
    return clientid, vuln_rd
  end

  def update_vuln_status(vuln_id, status)
    params = {
      :last_check => Time.now.to_i,
      :status => status
    }
    hash   = {
      :filter => {
        :id => vuln_id.to_i,
      },
      :fields => params
    }
    resp = request('/v1/objects/vuln/update', hash)
    resp
  end

  def find_vuln(object, params)
    filter = {
      :method    => object.params[:method],
      :domain    => object.params[:domain],
      :path      => object.params[:uri].gsub(/\?.*/, '')[0...256],
      :parameter => object.params[:point].to_s[0...256],
    }.merge(params)

    filter[:type] = filter[:type].to_s

    App.logger.info "filter: #{filter.inspect}"

    resp = request('/v1/objects/vuln', :filter => filter)

    resp && resp['body'][0]
  end

  def handle_validated(vuln, req_params)
    if App.config.extensions && App.config.extensions.key?('validated')
      validated = App.config.extensions['validated']

      if vuln[:extension]
        name = vuln[:extension].split('_').map(&:capitalize).join
        if App.config.extensions.key?(name) && App.config.extensions[name].key?(:validated)
          validated = App.config.extensions[name][:validated]
        end
      end

      req_params.merge! validated: validated
    end
  end

  def create_vuln_for_baseline(vuln, clientid, object, test_run_id)
    req_params = fill_vuln_params(vuln, object, test_tun: true)

    handle_validated(vuln, req_params)

    req_params.merge!(
      testrun_id: test_run_id.to_i,
      clientid:   clientid,
      scid:       vuln[:scid]
    )

    vuln = find_vuln(
      object,
      clientid:   clientid,
      type:       req_params[:type],
      testrun_id: test_run_id.to_i,
      scid:       vuln[:scid]
    )

    if vuln.nil?
      App.logger.info 'Creating new vulnerability...'
      resp = request('/v1/objects/vuln/create', req_params)
      vuln = resp && resp['body']
    end
    return vuln
  rescue => e
    App.logger.error(e)
    raise
  end

  def create_vuln(vuln, clientid, object, vuln_recheck)
    req_params = fill_vuln_params(vuln, object)

    handle_validated(vuln, req_params)

    req_params.merge!({ clientid: clientid })

    vuln = find_vuln(object, clientid: clientid, type: req_params[:type])

    req_params.merge!(vuln_recheck)

    resp = if vuln.nil?
      App.logger.info "creating new vulnerability..."
      request('/v1/objects/vuln/create', req_params)
    elsif %w(closed falsepositive).include? vuln['status']
      App.logger.info "reopening vulnerability ##{vuln['id']}..."
      request(
        '/v1/objects/vuln/update',
        :filter => { :id     => vuln['id'] },
        :fields => { :status => :open  }
      )
    else
      vuln
    end
    resp
  rescue => e
    App.logger.error(e)
    raise
  end

  def fill_vuln_params(vuln, object, opts = {})
    args = Marshal.load(Marshal.dump(vuln[:args])) || {}
    args.merge!({
      :method          => object.params[:method],
      :domain          => object.params[:domain],
      :path            => object.params[:uri].gsub(/\?.*/, '')[0...256],
      :parameter       => object.params[:point].to_s[0...256],
      :ip              => object.params[:ip],
      :port            => object.params[:port]
    })

    sp     = String.new(args[:path])
    sp    += '/' if sp[-1]!='/'
    sp[-1] = '*'
    time   = Time.at(object.params[:req].request_time.to_i)
    time   = time.strftime('%d.%m.%Y')

    param  = args[:parameter] || ''
    param  = "\"#{param}\"" if param.include?(' ')
    sp     = "\"#{sp}\""    if sp.include?(' ')
    time   = URI.escape(time)
    param  = URI.escape(param)
    sp     = URI.escape(sp)

    link   = "/search/attacks%20incidents%20#{sp}%20#{param}=%20#{time}"

    unless opts[:test_tun]
      args[:footers]              ||= {}
      args[:footers][:additional] ||= []
      args[:footers][:additional] << {
        :view   => 'attack_rechecker',
        :params => {
          :link => link
        }
      }
    end

    VulnTemplates.fill(vuln[:template], args)
  end
end

class Wallarm::API
  include WapiMixins
end
