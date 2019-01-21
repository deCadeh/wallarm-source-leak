# -*- encoding: utf-8 -*-

class XssValidatorJob
  def self.perform(job)
    GeneralJob.perform(job, :xss)
  end
end

