#!/usr/bin/env ruby
#

require 'optparse'

@options = {}
OptionParser.new do |opts|
	opts.banner = "Usage: autohack.rb [options]"
	opts.on("-f", "--file", "sample filename") do |v|
		@options[:file] = v
	end
	opts.on("-a", "--action", "action to take") do |v|
		@options[:action] = v
	end
	opts.on("-v", "--verbose", "verbose output") do |v|
		@options[:verbose] = v
	end
end.parse!
raise OptionParser::MissingArgument if @options[:file].nil?


