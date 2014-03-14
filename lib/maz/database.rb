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
$:.unshift(File.dirname(__FILE__))

require 'mongo'
require 'rubygems'
require 'pp'

module Maz
  class Database < Maz::Core

    def initialize
      @mongo = Mongo::Connection.new
      @mazdb = @mongo.db("maz_db")
      @store_db = @mazdb["storage"]
    end

    def db_exists?
      if @mazdb["storage"]
        return true
      else
        return false
      end
    end

    def update(entry, data)
      entry_id = @store_db.find("md5_hash" => "#{entry}")
    end

    def insert(data)
      entry_id = @store_db.insert(data)
      status("entry accepted for id: #{entry_id}")
    end

    def count_all
      count = @store_db.count.to_i
      return count
    end

    def stats
      pgreen("\n\t[ Database Statistics ]")
      pbwhite("\ntotal entries: ")
      pp count_all
      pbwhite("\ndatabase stats: ")
      @mazdb.stats().each_pair { |k,v| puts "#{k} : #{v}" }
      pbwhite("\nstorage collection: ")
      @store_db.stats().each_pair { |k,v| puts "#{k} : #{v}" }
      puts "\n"
    end

    def view_last
      result = @store_db.find_one.to_a
      return result
    end

    def view_all
      all = {}
      @store_db.find.each do |item|
        puts item.inspect
      end
      return all
    end

    def delete_entry(type, query)
      if type == "file"
        result = @store_db.remove("file_name" => "#{query}")
      elsif type == "md5"
        result = @store_db.remove("md5_hash" => "#{query}")
      elsif type == "sha1"
        result = @store_db.remove("sha1_hash" => "#{query}")
      end
      return result
    end

    def search(type, query, show=false)
      if type == "file"
        result = @store_db.find("file_name" => "#{query}").to_a
      elsif type == "md5"
        result = @store_db.find("md5_hash" => "#{query}").to_a
      elsif type == "sha1"
        result = @store_db.find("sha1_hash" => "#{query}").to_a
      end
      if result == []
        return false
      elsif result != [] && show
        return result
      elsif result != [] && show == false
        return true
      end
    end

  end
end

