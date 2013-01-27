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

require 'digest/md5'
require 'digest/sha1'

module Maz
  class Analyze < Maz::External

    def is_binary?(file)
      if File.exists?(file) && File.executable?(file)
        return true
      else
        return false
      end
    end

    def static(file_name)
      @info = {
        :file_name => file_name,
        :file_type => `file #{file_name}`.chomp,
        :file_size => File.size?(file_name),
        :time => Time.now,
        :md5_hash => Digest::MD5.hexdigest(File.read(file_name)),
        :sha1_hash => Digest::SHA1.hexdigest(File.read(file_name)),
      }
    end

    def submit(file_name)
      sample = static(file_name)
      sample[:shadow] = get_shadow([:md5_hash])
      return sample
    end
    
    # original from Malare project
    def string_analysis
      if self.is_binary?(@info[:file_name])
        lines = File.new(@info[:file_name], "r:ASCII-8BIT")
        lines.readlines.each do |line|
          network_strings(line)
          registry_strings(line)
          system_strings(line)
        end
      end
    end

    def get_shadow(hash)
      # query and retrieve shadowserver info
      return shadow_query(hash)
    end

    def get_anubis
      nil
    end

    def get_threatex(hash)
      return threatx_query(hash)
    end

  end
end


