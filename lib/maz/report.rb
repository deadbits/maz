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

require 'json'


module Maz
  class Report < Maz::Core

    def text(data)
      report = ""
      if data[:file_name]
        # check if the sample data we are using for the
        # report is pre-database entry or not. we use the
        # hash[:key] format for everything pre-db entry
        report += "\nFile Name:\t#{data[:file_name]}"
        report += "\nFile Type:\t#{data[:file_type]}"
        report += "\nFile Size:\t#{data[:file_size]}"
        report += "\n Location:\t#{data[:location]}"
        report += "\nSubmitted:\t#{data[:time]}"
        report += "\n MD5 Hash:\t#{data[:md5_hash]}"
        report += "\nSHA1 Hash:\t#{data[:sha1_hash]}"
        unless data[:shadow] == nil
          report += "\n\t[ ShaowServer Results ]"
          report += "\nFirst Seen:\t#{data[:shadow][:first]}"
          report += "\n Last Seen:\t#{data[:shadow][:last]}"
          report += "\n File Type:\t#{data[:shadow][:type]}"
          report += "\n\t[ Anti-Virus ]"
          data[:shadow][:avres].each { |av| report += "#{av}" }
          report += "\n"
        end
      elsif data["file_name"]
        report += "\nFile Name:\t#{data["file_name"]}"
        report += "\nFile Type:\t#{data["file_type"]}"
        report += "\nFile Size:\t#{data["file_size"]}"
        report += "\n Location:\t#{data["location"]}"
        report += "\nSubmitted:\t#{data["time"]}"
        report += "\n MD5 Hash:\t#{data["md5_hash"]}"
        report += "\nSHA1 Hash:\t#{data["sha1_hash"]}"
        unless data[:shadow] == nil
          report += "\n\t[ ShaowServer Results ]"
          report += "\nFirst Seen:\t#{data["shadow"]["first"]}"
          report += "\n Last Seen:\t#{data["shadow"]["last"]}"
          report += "\n File Type:\t#{data["shadow"]["type"]}"
          report += "\n\t[ Anti-Virus ]"
          data["shadow"]["avres"].each { |av| report += "#{av}" }
          report += "\n"
        end
        return report
      end
    end

    def save(data, output_file)
      if File.exist?(output_file)
        error("file #{output_file} all ready exists. please specify another output filename.")
        return false
      else
        status("saving report to: #{output_file}")
        fout = File.open(output_file, "w")
        fout.write(data)
        fout.close()
        status("report successfully created and saved.")
        return true
      end
    end

  end
end



