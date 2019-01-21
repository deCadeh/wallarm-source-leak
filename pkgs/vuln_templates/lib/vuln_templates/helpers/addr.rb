module VulnTemplates
  module Helpers
    private

    module Addr
      def dns_names_of_ip(ip, names)
        r  = "Host '#{ip}' is known as:"
        r += '<ul>'
        names.each do |name|
          r += "<li>#{name}</li>"
        end
        r += '</ul>'
        names.size>0 ? r : nil
      end

      def hosts_of_dns_name(name, hosts)
        r = "Domain '#{name}' is hosted at:"
        r += '<ul>'
        hosts.each do |host|
          r += "<li>#{host}</li>"
        end
        r += '</ul>'
        hosts.size>0 ? r : nil
      end
    end
  end
end

