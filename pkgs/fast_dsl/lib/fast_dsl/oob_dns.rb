# we use external dependency and should configure it before using gem
module FastDsl
  @oob_dns = nil

  def self.oob_dns
    @oob_dns
  end

  def self.oob_dns=(val)
    @oob_dns = val
  end
end
