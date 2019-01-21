require 'gumbo'

module FastDsl
  # just detect helpers
  module Helpers
    # extend gumbo class with our methods
    module ParsedHtml
      def extract_js(node = nil)
        node ||= self
        result = []

        result << node.children[0].to_s if node.respond_to?(:tag) && node.tag == :script

        if node.respond_to? :children
          node.children.each do |child|
            result += extract_js child
          end
        end

        result.compact
      end

      def extract_hrefs(node = nil)
        node ||= self
        result = []

        if node.respond_to?(:tag) && node.tag == :a
          attribute = node.attribute 'href'
          result << attribute.value if attribute
        end

        if node.respond_to? :children
          node.children.each do |child|
            result += extract_hrefs child
          end
        end

        result
      end

      def extract_marker_pos(marker, type, node = nil)
        node ||= self

        return false if node.is_a?(Gumbo::Whitespace) || node.is_a?(Gumbo::Text)

        if type == :tag && node.respond_to?(:original_tag_name)
          return node.start_pos.offset if Helpers.normalize_enconding(node.original_tag_name || '') =~ marker
        end

        if type == :attribute && node.respond_to?(:attribute)
          node.attributes.each do |attr|
            next unless Helpers.normalize_enconding(attr.original_name || '') =~ marker

            return node.start_pos.offset
          end
        end

        if node.class == Array
          node.each do |item|
            pos = extract_marker_pos(marker, type, item)
            return pos if pos
          end
        end

        node.children.each do |item|
          pos = extract_marker_pos(marker, type, item)
          return pos if pos
        end

        false
      end
    end

    module_function

    def parse_html(data)
      res = Gumbo.parse(Helpers.normalize_enconding(data))
      res.extend(Helpers::ParsedHtml)
      res
    end

    def normalize_enconding(str)
      h = { invalid: :replace, undef: :replace, replace: ' ' }
      str.encode('UTF-8', h).encode('UTF-16', h).encode('UTF-8').tr("\0", ' ')
    end

    def normalize_hash_enconding(hash)
      res = {}
      hash.each do |k, v|
        res[Helpers.normalize_enconding(k)] = Helpers.normalize_enconding(v)
      end
      res
    end
  end
end
