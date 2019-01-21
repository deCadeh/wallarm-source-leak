module VulnTemplates
  VERSION = '3.46.3'

  def self.version
    VERSION
  end

  def self.check_version?(needed_version)
    o = version.split('.').map { |i| i.to_i }
    n = needed_version.split('.').map { |i| i.to_i }
    return false if o[0]!=n[0]
    if n[1]==o[1]
      return n[2]<=o[2]
    else
      return n[1]<=o[1]
    end
  end
end
