require 'rkelly'

module FastDsl
  module Blocks
    class Detect
      module Rules
        # Detects any html marker in body
        class BodyHtml < BaseRule
          def initialize(tag, regexp)
            @tag    = tag
            @regexp = regexp
          end

          def marker
            "#{@tag} = #{@regexp}"
          end

          def run(opts)
            case @tag
            when 'js'
              js(opts)
            when 'href'
              href(opts)
            when 'attr'
              entity(:attribute, opts)
            else
              entity(:tag, opts)
            end
          end

          private

          def entity(type, opts)
            r = make_regexp(@regexp, opts)

            offset = opts.fetch(:dom).extract_marker_pos(r, type)

            offset && exploit_stamp(offset, opts.fetch(:body))
          end

          def js(opts)
            @js_parser ||= RKelly::Parser.new

            r = make_regexp(@regexp, opts)

            opts.fetch(:dom).extract_js.each do |script|
              variables = []

              begin
                ast = @js_parser.parse(script)

                variables = ast.map do |i|
                  i.respond_to?(:value) && i.value.class == String ? i.value : nil
                end
              rescue
                # nothing to do, RKelly is bugged
                next
              end

              variables.compact.each do |var|
                var = Helpers.normalize_enconding(var)

                next unless var =~ r

                return "<script> ... #{var} ... </script>"
              end
            end

            nil
          end

          def href(opts)
            r = make_regexp(@regexp, opts)
            opts.fetch(:dom).extract_hrefs.each do |val|
              val = Helpers.normalize_enconding(val)

              next unless val =~ r

              return "href=#{val}"
            end

            nil
          end
        end
      end
    end
  end
end
