# -*- encoding: utf-8 -*-

class SqliValidatorJob
  def self.perform(job)
    GeneralJob.perform(job, :sqli)
  end
end

