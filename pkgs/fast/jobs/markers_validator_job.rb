# -*- encoding: utf-8 -*-

class MarkersValidatorJob
  def self.perform(job)
    GeneralJob.perform(job, :fuzzer)

    # Add more markers jobs here
    #
    #   GeneralJob.perform(job, TYPE, true)
    #

  end
end


