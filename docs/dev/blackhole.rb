#!/usr/bin/env ruby
# blackhole2 deobfs
# say wooordddddd

require 'stringio'

def banner
  puts "\n\tblackhole2 - deobfuscation utility"
  puts "\thelper script for the maz project"
  puts "\tusage: ./bhdo.rb <obsfucated file>"
  puts "\n"
end

def doit
  unless File.exists?(@file_name) == false
    File.open(@file_name, "rb") { |f| content << f.read }
    attributes = content.scan(/\s(\d{1,2})\=\"(.*?)\"/)
    (0...attributes.length).each do |i|
      attributes[i][0] = attributes[i][0].to_i
    end
    attributes.sort!
    (0...attributes.length).each do |i|
        code << attributes[i][1]
    end
    code.gsub!(/[^012a-z3-9]/,'')
    code = StringIO.new(code)
    while true
      a = code.read(2)
      if a.kind_of?(String)
        deobf << a.to_i(base).chr
      else
        break
      end
    end
  File.open("#{@file_name}_clean.html", "w") { |f| f.write(deobf) }
  puts "[*] deobfuscation completed!"
  puts "[*] output saved as: #{@file_name}_clean.html"
end

content = ""
code    = ""
base    = 31
deobf   = ""

if ARGV[0] == nil
  banner
  exit(0)
else
  @file_name = ARGV[0]
  puts "[~] starting deobfuscation process..."
  doit
end


