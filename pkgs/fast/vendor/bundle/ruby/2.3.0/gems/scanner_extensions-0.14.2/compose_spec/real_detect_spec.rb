require 'spec_helper'

describe ScannerExtensions::Extensions do
  context 'does not detect' do
    context 'xss' do
      (1..5).to_a.each do |i|
        include_examples(
          'false positive',
          ext:  'XssDetect',
          name: "/xss/false.#{i}.php?test=*",
          args: {
            'http_params' => {
              host:          'scanner-test-app',
              port:          80,
              url:           "/xss/false.#{i}.php",
              param_name:    'test',
              request_class: Net::HTTP::Get
            }
          }
        )
      end
    end
  end

  context 'detects' do
    context 'bo0om.xss' do
      (1..17).to_a.each do |i|
        include_examples(
          'detect',
          ext:  'XssDetect',
          name: "/xss/bo0om.php?test=#{i}&id=*",
          args: {
            'http_params' => {
              host:          'scanner-test-app',
              port:          80,
              url:           "/xss/bo0om.php?test=#{i}&",
              param_name:    'id',
              request_class: Net::HTTP::Get
            }
          }
        )
      end
    end

    context 'xss' do
      (1..5).to_a.each do |i|
        include_examples(
          'detect',
          ext:  'XssDetect',
          name: "/xss/true.#{i}.php?test=*",
          args: {
            'http_params' => {
              host:          'scanner-test-app',
              port:          80,
              url:           "/xss/true.#{i}.php",
              param_name:    'test',
              request_class: Net::HTTP::Get
            }
          }
        )
      end
    end

    context 'sqli' do
      (1..7).to_a.each do |i|
        include_examples(
          # Do not detect time sqlite injections
          [1, 2, 3, 4, 5, 6, 7].include?(i) ? 'pending detect' : 'detect',
          ext:  :sqli,
          name: "/sqli/true.#{i}.php?test=*",
          args: {
            'http_params' => {
              host:          'scanner-test-app',
              port:          80,
              url:           "/sqli/true.#{i}.php",
              param_name:    'test',
              request_class: Net::HTTP::Get,
              entry_value:   1
            }
          }
        )
      end
    end
  end
end
