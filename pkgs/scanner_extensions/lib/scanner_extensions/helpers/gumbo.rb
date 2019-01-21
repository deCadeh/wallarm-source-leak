require 'gumbo'
require 'digest/crc32'

require_relative './string'

module ScannerExtensions
  module Helpers
    module Gumbo
      module_function

      def parse(data)
        ::Gumbo.parse(data.normalize_enconding)
      end
    end
  end
end

class Gumbo::Document
  def find_scripts(node = nil)
    node   = self unless node
    result = []

    if node.respond_to?(:tag) && node.tag == :script
      result << node.children[0].to_s
    end

    if node.respond_to? :children
      for child in node.children
        result += find_scripts child
      end
    end
    result.compact
  end

  def find_hrefs(node = nil)
    node   = self unless node
    result = []

    if node.respond_to?(:tag) && node.tag == :a
      attribute = node.attribute 'href'
      result << attribute.value if attribute
    end

    if node.respond_to? :children
      for child in node.children
        result += find_hrefs child
      end
    end
    result
  end

  def contains(another, deep = nil)
    contain_tree(self, another, deep)
  end

  def contain_tree(op1, op2, deep = nil, cur_deep = 0)
    res = 0
    cur_deep += 1
    if deep
      return false if cur_deep > deep
    end
    return false unless op1.class == op2.class
    if op1.class == Array
      i1 = 0
      i2 = 0
      while i1 < op1.size && i2 < op2.size
        tmp = contain_tree(op1[i1], op2[i2], deep, cur_deep)
        if tmp
          res += tmp
          i1  += 1
          i2  += 1
        else
          i1  += 1
          res += 1
        end
      end
      if i2 == op2.size
        return res + op1.size - i1
      else
        return false
      end
    else
      return false unless op1.type == op2.type
      if op1.respond_to? :tag
        return false unless op1.tag == op2.tag
      end
      if op1.respond_to? :children
        tmp = contain_tree(op1.children, op2.children, deep, cur_deep)
        if tmp
          res += tmp
        else
          return false
        end
      end
      return res
    end
  end

  def xss?
    has_marker? self
  end

  def has_marker?(node)
    return if node.is_a? Gumbo::Whitespace
    return if node.is_a? Gumbo::Text
    if node.respond_to? :original_tag_name
      return true, node.start_pos.offset if node.original_tag_name == 'wlrm'
    end
    if node.respond_to? :attribute
      return true, node.start_pos.offset if node.attribute('wlrm')
    end
    if node.class == Array
      node.each do |item|
        has_marker, pos = has_marker?(item)
        return true, pos if has_marker
      end
    end
    node.children.each do |e|
      has_marker, pos = has_marker?(e)
      return true, pos if has_marker
    end
    [false, nil]
  end

  def ==(op2)
    cmp_tree(self, op2)
  end

  def cmp_tree(op1, op2)
    return false unless op1.class == op2.class
    if op1.class == Array
      return false unless op1.size == op2.size
      for i in 0...op1.size do
        return false until cmp_tree(op1[i], op2[i])
      end
      return true
    end
    return false unless op1.type == op2.type
    if op1.respond_to? :tag
      return false unless op1.tag == op2.tag
    end
    if op1.respond_to? :children
      return false until cmp_tree(op1.children, op2.children)
    end
    true
  end

  def crc_hash(max_deep = 8)
    crc = Digest::CRC64.new
    crc_tree(self, crc, max_deep)
    crc.hexdigest
  end

  def crc_tree(obj, crc, max_deep = 8, deep = 0)
    return if obj.class == Gumbo::Text
    return if deep > max_deep
    crc << obj.class.to_s
    if obj.class == Array
      obj.each do |item|
        crc_tree(item, crc, max_deep, deep + 1)
      end
      return
    end
    crc << obj.type.to_s
    crc << obj.tag.to_s if obj.respond_to? :tag
    crc_tree(obj.children, crc, max_deep, deep + 1) if obj.respond_to? :children
  end
end
