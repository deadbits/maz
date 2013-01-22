#!/usr/bin/env ruby
##
# Malware Analysis Zoo
# https://github.com/ohdae/maz
# name: external.rb
# desc: query external services for info
# on submitted malware samples
##

module Maz
  class External
    require 'net/http'
    require 'nokogiri'
    require 'uri'
    require 'open-uri'
    require 'crack'
    require 'json'

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

    