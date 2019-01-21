# -*- encoding: utf-8 -*-

require 'ipaddr'

module Proton::RequestIpPort
  def ip_port(opts = {resolve_dns: true})
    result = []

    if self.server_addr
      result << [self.server_addr.to_s, self.server_port]
    end

    values = []
    entry = self.header('HOST')
    unless entry.nil?
      values << entry.value
      Array(entry.value_types[:array]).each do |e|
        values << e.value
      end
    end

    port_defined_in_host = false

    values.compact.each do |val|
      host  = val.sub(/:[0-9]+$/, '')
      if host != val
        port = val.sub( /.*:/, '').to_i
        port_defined_in_host = true
      else
        port = 80
      end
      host  = host.sub(/.*\/\//, '').sub( /\/.*/, '')
      begin
        TCPSocket.gethostbyname(host)[3..-1].each do |ip|
          result << [ip, port]
          result << [ip, self.server_port]
        end
      rescue
      end
    end

    result.map! do |ip, port|
      ip = IPAddr.new(ip).native.to_s
      port ||= 80
      [ip, port.to_i]
    end

    result.reject!{ |ip, port| bad_ip?( ip) }
    result.uniq!

    if opts[:resolve_dns]
      # when attack rechecker
      result
    else
      # when fast proxy
      if result.empty?
        []
      else
        if result[0][0] == '127.0.0.1'
          if result[1]
            result[0][0] = result[1][0]
            result[0][1] = result[1][1] if port_defined_in_host
          end
          [result[0]]
        else
          [result[0]]
        end
      end
    end
  end

  private

  def bad_ip?( ip)
    if App.config.private_scan
      return false
    end

    nets = %w( 10.0.0.0/8 127.0.0.0/8 172.16.0.0/12 169.254.0.0/16
               192.168.0.0/16 fe80::/10 fec0::/10 fc00::/7 ::1/128 )

    nets.each do |net|
      return true if IPAddr.new(net).include? ip
    end

    false
  end
end

class Proton::Request;               include Proton::RequestIpPort; end
class Proton::SerializedRequest::V1; include Proton::RequestIpPort; end
class Proton::SerializedRequest::V2; include Proton::RequestIpPort; end
class Proton::SerializedRequest::V3; include Proton::RequestIpPort; end
class Proton::SerializedRequest::V4; include Proton::RequestIpPort; end
