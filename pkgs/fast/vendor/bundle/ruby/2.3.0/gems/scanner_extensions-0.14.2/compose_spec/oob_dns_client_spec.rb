require 'spec_helper'

describe ScannerExtensions::Helpers::OobDnsClient do
  it 'compatible with oob-dns service' do
    ScannerExtensions::Helpers::OobDnsClient.config = {
      'host' => 'oob-dns',
      'port' => '8080'
    }
    token = ScannerExtensions::Helpers::OobDnsClient.create
    array = ScannerExtensions::Helpers::OobDnsClient.get token
    expect(array).to eq []
    begin
      Resolv::DNS.new(
        nameserver_port:  [['oob-dns', 5053]]
      ).getresources(token, Resolv::DNS::Resource::IN::A)
    rescue
    end
    array = ScannerExtensions::Helpers::OobDnsClient.get token
    expect(array.size).to be > 0
  end
end
