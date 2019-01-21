require 'spec_helper'

describe ScannerExtensions::Extensions::ImageTragickSsrf do
  let(:extension) { ScannerExtensions::Extensions::ImageTragickSsrf.new }

  before(:all) do
    ScannerExtensions::Helpers::OobDnsClient.config = {
      'host' => 'oob-dns',
      'port' => '8080'
    }
  end

  [/ping -c 1 (.+)"/].each do |_payload|
    it 'detects vuln' do
      begin
        port       = get_open_port
        web_server = WebServer.new(port)
        web_server.server.mount_proc '/' do |req, res|
          addr = req.query['test'].scan(%r{\/\/(.*?)\/}).flatten[0]
          begin
            Resolv::DNS.new(
              nameserver_port:  [['oob-dns', 5053]]
            ).getresources(addr, Resolv::DNS::Resource::IN::A)
          rescue
          end
          res.body = 'test'
        end
        web_server.start
        params = {
          'http_params' => {
            host:          '127.0.0.1',
            port:          port,
            url:           '/',
            param_name:    'test',
            request_class: Net::HTTP::Get
          }
        }
        object = ScannerExtensions::Wrappers::Object.new params
        extension.run(object, sleep: 1)
        expect(object.vulns.size).to eq 1
        vuln = object.vulns[0]
        expect(vuln[:args][:exploit_example].index('oob-dns').nil?).to eq false
        # 2 ips: 1-st from curl, 2-nd from footer
        expect(
          VulnTemplates.fill(
            vuln[:template],
            vuln[:args].merge(ip: '123', port: '123')
          )[:exploit_example].scan(/((?:\d+\.){3}\d+)/).size
        ).to eq 2
      ensure
        web_server.stop
      end
    end
  end

  it 'does not detect fp' do
    begin
      port       = get_open_port
      web_server = WebServer.new(port)
      web_server.server.mount_proc '/' do |_req, res|
        res.body = 'test'
      end
      web_server.start
      params = {
        'http_params' => {
          host:          '127.0.0.1',
          port:          port,
          url:           '/',
          param_name:    'test',
          request_class: Net::HTTP::Get
        }
      }
      object = ScannerExtensions::Wrappers::Object.new params
      extension.run(object, sleep: 1)
      expect(object.vulns.size).to eq 0
    ensure
      web_server.stop
    end
  end
end
