# -*- encoding: utf-8 -*-

# require 'proton'

class Proton::Point
  def include?(point)
    op1 = self.point
    op2 = point.point
    return false unless op1.size==op2.size
    for i in 0...op1.size do
      if op1[i].size==2 && op2[i].size==2
        next if op1[i][0]==op2[i][0] && op1[i][1]==:all
      end
      return false unless op1[i]==op2[i]
    end
    return true
  end

  def from_all(req, detect_type)
    return self unless self.multi?
    req.attacks(5000).each do |attack|
      type = Proton.attack_type_name_by_id(attack[:type])
      next unless type == detect_type
      next unless self.include?(attack[:point])
      return attack[:point]
    end
    return nil
  end

  def start_with?(array_point)
    op1 = self.point
    for i in 0...array_point.size do
      return false unless op1[i] == array_point[i]
    end
    return true
  end
end
