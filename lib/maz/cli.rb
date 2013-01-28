#!/usr/bin/env ruby
##
# Malware Analysis Zoo
# https://github.com/ohdae/maz
##
# MAZ is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MAZ is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MAZ.  If not, see <http://www.gnu.org/licenses/>.
##

require File.expand_path("#{File.dirname __FILE__}" + "/../maz")
require 'trollop'

module Maz
  class CLI < Maz::Core
    @@Database = Maz::Database.new
    @@Analyze = Maz::Analyze.new

    def initialize
      opts = Trollop::options do
        version = "beta version 0.5 (c) 2013 - Adam M. Swanda"
        banner <<-EOS
      Malware Analysis Zoo :: command line interface 
      website:  https://github.com/ohdae/maz

      maz-cli.rb is for quick analysis and sample submissions. all samples
      you submit through this script will be analyzed, stored in the maz database
      and reports will be generated and saved. for more fine tuned control over
      your maz experience, check out the maz-console.rb application.

      Usage: maz-cli [options] [args]
      Options:
      EOS
        opt :file, "Sample file path to analyze and submit", :type => String
        opt :report, "Display text report after analysis", :default => true
        opt :query, "Search MAZ database for MD5 hash", :type => String
        opt :count, "Display last [count] submissions", :type => Integer
        opt :stats, "Show statistics on indexed samples and database entries", :default => false
      end
      # perform some quick error checks on our options and arguments
      if opts[:file]
        if File.exists?(opts[:file])
          submit(opts[:file])
        else
          Trollop::die :file, "does not seem to exist"
        end
      elsif opts[:count] and opts[:count].to_i <= 0
        Trollop::die :count, "must be a positive number"
      elsif opts[:query]
        result = @@Database.search_md5(opts[:query])
        unless result == nil
          pbwhite("\tSearch Results: ")
          pp result
        end
      elsif opts[:stats]
        @@Database.stats
      end
    end

    def submit(file_name)
      status("starting analysis of sample: #{file_name}")
      sample = @@Analyze.submit(file_name)
      @@Database.create(sample)
      text_report(sample)
    end

  end
end












