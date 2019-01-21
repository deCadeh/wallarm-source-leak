module ScannerExtensions
  module Extensions
    # Detect sqli by dom difference
    class BlindSqli < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :sqli
        @components          = :rechecker

        @defaults = {
          timeout: 15,
          html_deep: 32
        }

        @falsy = [
          '%<entry_id>s and %<id>s=42',
          '%<entry_id>s and %<id>s=42--wlrm',
          "%<entry_id>s' and %<id>s=42 and 'wlrm'='wlrm",
          '%<entry_id>s" and %<id>s=42 and "wlrm"="wlrm',
          "%<entry_id>s%%' and %<id>s=42 and '%%'='",
          '%<entry_id>s%%" and %<id>s=42 and "%%"="',
          '%<entry_id>s) and %<id>s=42 and (1=2',
          "%<entry_id>s') and %<id>s=42 and ('wlrm'='wlrm",
          '%<entry_id>s") and %<id>s=42 and ("wlrm"="wlrm'
        ]
        @truthy = [
          '%<entry_id>s and %<id>s=%<id>s',
          '%<entry_id>s and %<id>s=%<id>s--wlrm',
          "%<entry_id>s' and %<id>s=%<id>s AND 'wlrm'='wlrm",
          '%<entry_id>s" and %<id>s=%<id>s AND "wlrm"="wlrm',
          "%<entry_id>s%%' and %<id>s=%<id>s AND '%%'='",
          '%<entry_id>s%%" and %<id>s=%<id>s AND "%%"="',
          '%<entry_id>s) and %<id>s=%<id>s AND (1=1',
          "%<entry_id>s') and %<id>s=%<id>s AND ('wlrm'='wlrm",
          '%<entry_id>s") and %<id>s=%<id>s AND ("wlrm"="wlrm'
        ]
      end

      def run(object, params)
        # Disable false positives for until a better day
        return

        params = @defaults.merge(params)

        make_request = proc do |payload|
          object.http(
            value:        payload,
            timeout:      params[:timeout],
            open_timeout: params[:open_timeout]
          )
        end

        access_request = make_request.call(String.get_rand(8))

        # check http access
        url_accessible = success? access_request
        return unless url_accessible

        normal_responses = []

        id = 1000 + rand(1000)

        # get stat for responses to eliminate false positives if search
        # string handles 'AND' and return extra DOM result for it
        [id.to_s, 'and', "'andd'", '"andd"'].each do |data|
          res = make_request.call(data)
          res = success? res
          if [id.to_s, 'and'].include? data
            return unless res
          end
          next unless res
          normal_responses << res
        end

        @falsy.each_with_index do |payload, index|
          falsy_resp  = make_request.call(format(payload, entry_id: 1, id: id))
          truthy_resp = make_request.call(format(@truthy[index], entry_id: 1, id: id))

          falsy_dom,  falsy_size  = parse_resp(falsy_resp)
          truthy_dom, truthy_size = parse_resp(truthy_resp)

          next unless falsy_dom && truthy_dom

          # skip FP if response for just 'AND' equals truthy_resp
          skip = false
          normal_responses.each do |resp|
            truthy_resp_is_fp = truthy_dom.crc_hash(params[:html_deep]) == resp.crc_hash(params[:html_deep])
            skip = true if truthy_resp_is_fp
          end
          next if skip

          # truthy_dom should contain extra DOM elements
          cond   = falsy_dom.crc_hash(params[:html_deep]) != truthy_dom.crc_hash(params[:html_deep])
          metric = truthy_dom.contains(falsy_dom, params[:html_deep])

          next unless cond && metric

          # verify truthy_resp with another id
          verifying_id    = - (1000 + rand(1000))
          verifying_resp  = make_request.call(format(@truthy[index], entry_id: 1, id: verifying_id))
          verifying_dom,_ = parse_resp(verifying_resp)

          next unless verifying_dom

          # verifying_dom should eq truthy_dom
          if truthy_dom.crc_hash(params[:html_deep]) != verifying_dom.crc_hash(params[:html_deep])
            next
          end

          # verifying_dom should also contain extra DOM elements
          unless verifying_dom.contains(falsy_dom, params[:html_deep])
            next
          end

          # verify falsy_resp
          verifying_falsy_resp   = make_request.call(format(payload, entry_id: 1, id: 1000 + rand(1000)))
          verifying_falsy_dom, _ = parse_resp(verifying_falsy_resp)

          if falsy_dom.crc_hash(params[:html_deep]) != verifying_falsy_dom.crc_hash(params[:html_deep])
            next
          end

          unless truthy_dom.contains(verifying_falsy_dom, params[:html_deep])
            next
          end

          falsy_curl  = object.curl_helper(url_code: false, value: format(payload, entry_id: 1, id: id))
          truthy_curl = object.curl_helper(url_code: false, value: format(@truthy[index], entry_id: 1, id: id))

          object.vuln(
            extension: 'blind_sqli',
            template:  '/sqli/blind_detect',
            binding:   :protocol,
            args:      {
              curl1:   falsy_curl,
              curl2:   truthy_curl,
              size1:   falsy_size,
              size2:   truthy_size,
              metric:  metric
            }
          )
          return
        end
      end

      private

      def parse_resp(response)
        return false, nil if response.nil?
        return false, nil if response.body.nil?
        return false, nil if response.code.to_i != 200
        body = response.body.normalize_enconding
        [ScannerExtensions::Helpers::Gumbo.parse(body), body.size]
      end

      def success?(response)
        return false if response.nil?
        return false if response.body.nil?
        return false if response.code.to_i != 200
        body = response.body.normalize_enconding
        ScannerExtensions::Helpers::Gumbo.parse body
      end
    end
  end
end
