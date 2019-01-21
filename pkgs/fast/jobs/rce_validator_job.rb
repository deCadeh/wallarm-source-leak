# -*- encoding: utf-8 -*-

class RceValidatorJob
  def self.perform(job)
    GeneralJob.perform(job, :rce)
  end
end

