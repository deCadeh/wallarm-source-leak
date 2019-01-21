# -*- encoding: utf-8 -*-

class FuzzerJob
  def self.perform(job)
    GeneralJob.perform(job, :fuzzer)
  end
end

