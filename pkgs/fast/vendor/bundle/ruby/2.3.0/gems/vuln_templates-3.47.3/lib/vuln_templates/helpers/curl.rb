module VulnTemplates
  module Helpers
    private

    module Curl
      def headers(http_response)
        res  = ""
        res += "HTTP/#{http_response.http_version} #{http_response.code} #{http_response.msg}\n"
        http_response.header.each_header do |key,value|
          res += "#{key.capitalize}: #{value}\n"
        end
        res[0...-1]
      end

      def curl(params)
        params = {
          :url      => '/',
          :protocol => :http,
          :port     => 80
        }.merge(params)
        if !params[:host]
          raise ArgumentError, 'Missing host'
        end
        hash = {}
        hash[:cmd] = '$ curl -k -g'
        if params[:vhost]
          str          = "Host: #{params[:vhost]}"
          hash[:vhost] = "-H #{wq(str)}"
        end
        curl_I = false
        if params[:curl_params]
          params[:curl_params].each do |k,v|
            hash['curl_' + k.to_s] = v
            curl_I = true if v == '-I'
          end
        end
        hash['curl_-L'] = '-L' unless curl_I
        if params[:form_data]
          data = ''
          params[:form_data].each do |param, value|
            data += "#{param}=#{CGI.escape(value)}&"
          end
          data = data[0...-1]
          hash[:post_data] = "--data #{wq(data)}"

          params[:headers] ||= {}
          params[:headers]['Content-Type'] = 'application/x-www-form-urlencoded'
        end
        if params[:headers]
          params[:headers].delete_if { |k, _| k =~ /Content-Length/i }
          params[:headers].each do |k,v|
            str                      = "#{k}: #{v}"
            hash['header_' + k.to_s] = "-H #{wq(str)}"
          end
        end
        hash[:url] = "#{params[:protocol]}://#{params[:host]}:#{params[:port]}#{params[:url]}"
        case params[:method]
        when :get
          if params[:get_params]
            hash[:url] += '?'
            params[:get_params].each do |param, value|
              hash[:url] += "#{param}=#{value}&"
            end
            hash[:url] = hash[:url][0...-1]
          end
        when :post
          hash[:post_data] = "--data #{wq(params[:post_data])}"
        when :options
          hash[:cmd] << ' -X OPTIONS'
        else
          # nothing to do
        end
        if params[:path_as_is]
          hash[:cmd] << ' --path-as-is'
        end
        hash[:url] = wq(hash[:url])
        result = hash.each_value.to_a.join(' ')
        if params[:resp_headers]
          if params[:resp_headers].is_a? Net::HTTPResponse
            result += "\n\n"
            result += headers(params[:resp_headers])
          else
            result += "\n\n"
            result += params[:resp_headers]
          end
        end
        if params[:grep_params]
          grep_regexp = params[:grep_params][:grep_regexp]
          grep_command = ' | grep %{grep_args} "%{grep_regexp}"'
          grep_args = if params[:grep_params][:pzo] == true
                        '-Pzo'
                      elsif  params[:grep_params][:o] == true
                        '-Eao'
                      else
                        '-Ea'
                      end
          result += format(grep_command, { grep_args: grep_args,
                                           grep_regexp: grep_regexp })
        end
        if params[:resp]
          result += "\n\n"
          result += params[:resp].gsub("\r\n", "\n")
        end
        return result
      end

      private

      def wq(str)
        str ||= ''
        str = str.gsub('\\', %q[\&\&])

        str = str.gsub('"') { %q[\\"] }
        str = str.gsub('$') { %q[\\$] }
        str = str.gsub('`') { %q[\\`] }

        str = str.gsub('!') { %q["'!'"] }

        str = str.gsub("\n") { '"$\'\n\'"' }

        '"' + str + '"'
      end
    end
  end
end

