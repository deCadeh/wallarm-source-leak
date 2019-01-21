require_relative './rule_maker'

module FastDsl
  module Blocks
    # extend detect class
    class Detect
      # parse YAML to single rules
      class Parser
        def initialize(detect)
          detect ||= %w[response oob]
          detect = expand_root(detect)

          init_flat_rules

          parse(detect)

          normalize!
        end

        private

        include RuleMaker

        def expand_root(detect)
          detect.map do |item|
            case item
            when 'response'
              { 'response' => %w[body headers] }
            when 'oob'
              { 'oob' => 'dns' }
            else
              item
            end
          end
        end

        def parse(detect)
          detect.each do |hash|
            hash.each do |k, v|
              case k
              when 'oob'
                @oob_dns = true
              when 'response'
                parse_response(v)
              else
                raise
              end
            end
          end
        end

        def normalize!
          @body_html.map! { |entity| entity == 'attribute' ? 'attr' : entity }

          [@status_regexp, @body_regexp, @full_headers_regexp, @body_html].each(&:uniq!)
        end

        def parse_response(array)
          array.each do |item|
            case item
            when 'body'
              @body_any_marker = true
            when 'headers'
              @headers_any_marker = true
            else
              item.each do |k, v|
                case k
                when 'body'
                  case v
                  when String
                    @body_regexp << v
                  when Array
                    parse_body(v)
                  else
                    raise
                  end
                when 'headers'
                  case v
                  when String
                    @full_headers_regexp << v
                  when Array
                    @headers_regexp += v
                  else
                    raise
                  end
                when 'status'
                  @status_regexp << v
                else
                  raise
                end
              end
            end
          end
        end

        def parse_body(array)
          array.each do |item|
            case item
            when 'html'
              @body_any_html = true
            else
              item.each { |k, v| k == 'html' && parse_html(v) }
            end
          end
        end

        def parse_html(array)
          array.each do |item|
            case item
            when String
              @body_html << item
            else
              @body_html_regexp << item
            end
          end
        end
      end
    end
  end
end
