# -*- encoding: utf-8 -*-

class PtravValidatorJob
  def self.perform(job)
    GeneralJob.perform(job, :ptrav)
  end
end

