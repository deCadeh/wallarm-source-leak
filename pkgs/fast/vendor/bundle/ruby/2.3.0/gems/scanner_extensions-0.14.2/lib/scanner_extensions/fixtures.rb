module ScannerExtensions
  # Some useful text data
  module Fixtures
    path_to = proc do |filename|
      relative_path = format('/fixtures/%<filename>s', filename: filename)
      path = File.expand_path(File.dirname(__FILE__)) + relative_path
      File.readlines(path).map(&:chomp).join
    end
    PAYLOADS = {
      'cve-2017-9805' => path_to.call('cve-2017-9805.xml')
    }.freeze
  end
end
