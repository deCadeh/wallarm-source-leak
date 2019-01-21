# -*- encoding: utf-8 -*-

class XxeValidatorJob
  def self.perform(job)
    GeneralJob.perform(job, :xxe)
  end
end

