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

module Maz
  class External
    require 'net/http'
    require 'nokogiri'
    require 'uri'
    require 'open-uri'
    require 'crack'
    require 'json'
    
    # the shadow_query and threatx_query functions are taken and minimized (with slight edits)
    # the from Shadowserver and ThreatExpert ruby gems
    def shadow_query(md5_hash)
      url = URI.parse("http://innocuous.shadowserver.org/api/?query=#{md5_hash}")
      request = Net::HTTP::Get.new("#{url.path}?#{url.query}")
      http = Net::HTTP.new(url.host, url.port)
      req = http.request(request)
      unless req.body.include?("No match found")
        result = req.body
        lines = result.split("\n")
        md5, sha1, first, last, type, ssdeep = lines[0].gsub(/\"/,'').split(/,/)
        avresults = JSON.parse(lines[1])
        @shadow_report = {
          :md5 => md5,
          :sha1 => sha1,
          :first => first,
          :last => last,
          :type => type,
          :ssdeep => ssdeep,
          :avres => avresults
        }
        return @shadow_report
      end
      return nil
    end

    def threatx_query(md5_hash)
      url = "http://www.threatexpert.com/report.aspx?md5=#{md5_hash}&xml=1"
      request = Net::HTTP::Get.new("#{url.path}?#{url.query}")
      http = Net::HTTP.new(url.host, url.port)
      req = http.request(request)
      unless req.body.include?("<status>not_found</status>")
        result = req.body
        final = Crack::XML.parse(result)
        return final
      end
      return nil
    end

  end
end

    
