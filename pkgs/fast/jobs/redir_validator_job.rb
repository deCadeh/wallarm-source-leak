# -*- encoding: utf-8 -*-

class RedirValidatorJob
  def self.perform(job)
    GeneralJob.perform(job, :redir)
  end
end

