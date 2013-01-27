#!/usr/bin/env ruby
##
# Malware Analysis Zoo
# name: console.rb
# desc: this is the console interface
# to MAZ. you can analyze all the malwares
# from here :D
##

require 'readline'
require File.expand_path("#{File.dirname __FILE__}" + "/../maz")

module Maz
  class Console < Maz::Core
    @@Analyze = Maz::Analyze.new
    @commands = [ "help", "report", "search", "recent", "exit", "quit", "load", "analyze",
      "cuckoo", "anubis", "vtotal", "threatx" ]

    def help_menu
      puts %{

        for full support, review the files in the 'docs' directory.
        in this menu, '[sample]' refers to any of the following:
        md5 hash - sha256 hash - filename - mID

     :::General Commands:::
      help                         -   display this menu
      report [html/txt] [sample]   -   generate report on [sample]
      search [sample]              -   query database for [sample]
      recent [count]               -   show [count] most recent submissions
        exit                       -   shutdown the MAZ console
     
      :::Analysis Commands:::
        load [file/directory]      -   add [file] or [directory] to queue
     analyze [file]                -   analyze [file], report and submit to database
      cuckoo [sample]              -   spin up [sample] in Cuckoo instance
      anubis [sample]              -   submit [sample] to Anubis and get report 
      vtotal [sample]              -   submit [sample] to VirusTotal and get report
     threatx [sample]              -   query ThreatExpert for [sample]
      }
    end

    #def dispatch(command, *args)
    #  @command.each_pair do |cmd, func|
    #    if cmd =~ /command/
    #      Maz::Core.status("executing ...")
    #      execute.func(*args)
    #    end
    #  end
    #end

    def initialize
      comp = proc { |s| @commands.grep ( /^#{Regexp.escape(s)}/ ) }
      Readline.completion_append_character = " "
      Readline.completion_proc = comp

      while cmd = Readline.readline("maz >> ", true).chomp
        if cmd == "exit"
          status("shutting down MAZ console ...")
          exit
        elsif cmd == "help"
          help_menu
        elsif cmd.include?("search")
          query = cmd.split(" ")[1]
          result = @@Database.search_file(query)
          unless result == nil
            puts "Search Result: #{result}"
          end
        elsif cmd == "stats"
          @@Database.stats
        elsif cmd.include?("analyze")
          filename = cmd.split(" ")[1].chomp
          analyze(filename)
        else
          error("command #{cmd} is not yet available.")
        end
      end
    end
  end
end


