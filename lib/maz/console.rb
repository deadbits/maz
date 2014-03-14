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
      "anubis", "vtotal", "threatx" ].sort

    def help_menu
      puts %{

        for full support, review the files in the 'docs' directory.

     :::General Commands:::
        help                       -   display this menu
      report [html/txt] [sample]   -   generate report on [sample]
      search [type] [data]         -   query db for [md5/sha1/name] of [data]
      recent                       -   show most recent submission
      delete [sample md5]          -   remove [sample] from database completely
       stats                       -   display database statistics
       clear                       -   clears the console screen
        exit                       -   shutdown the MAZ console

      :::Analysis Commands:::
        load [file/directory]      -   add [file] or [directory] to queue
     analyze <queue> [file]        -   analyze [file], report and submit to database
        queue                      -   view queued sample list
         tag [sample] [tags]       -   add custom tags to [sample] in db. use comma separated tags
      anubis [sample]              -   submit [sample] to Anubis and get report
      vtotal [sample]              -   submit [sample] to VirusTotal and get report
     threatx [sample]              -   query ThreatExpert for [sample]
      }
    end

    def search(input)
      type, query = input.split(" ")[1], input.split(" ")[2]
      if type.downcase == "md5"
        result = @@Database.search("md5", query, true)
      elsif type.downcase == "sha1"
        result = @@Database.search("sha1", query, true)
      elsif type.downcase == "file"
        result = @@Database.search("file", query, true)
      else
        error("#{type} is not a valid search type")
      end
      unless result == nil
        pbwhite("Search Results: ")
        pp result
      end
    end

    def queue_add(path)
      @queue = []
      path = path.split(" ")[1].chomp
      if File.directory?(path)
        pbwhite("#{path} is a directory. All files in this location will be added to the queue.")
        @queue = load_directory(path)
      elsif File.exist?(path)
        status("added sample #{path} to queue ...")
        @queue << path
      end
    end

    def manage_tags
      pbwhite("\nTo start adding tags to your samples, first start by entering")
      pbwhite("a sample name or md5 into the prompt below. after the sample is")
      pbwhite("found and queued, tags can be entered as comma separated values.")
      pbwhite("save your tags by hitting `enter`. return to the main console with")
      pbwhite("`home`")

      stty_pre = `stty -g`.chomp
      prompt = white(bold("sample >> "))

      while cmd = Readline.readline("#{prompt}", true).chomp
        if cmd == "home"
          status("returning to main menu")
          initialize

        elsif cmd == ""
          error("please enter a valid sample name or command")

        elsif search(cmd, "md5", show=false)
          sample = search(cmd, "md5", show=false)
          prompt = white(bold("tags >> "))
          while cmd = Readline.readline("#{prompt}", true).chomp
            if cmd == ""
              info("no tags were entered. returning to main console ...")
              initialize
            else
              begin
                tags = cmd.split(",")
                sample[:tags] = tags
                @@Database.update(sample)
              rescue
                error("tags msut be entered as comma separated values")
              end
            end
          end
        end
      end

    end

    def initialize
      Core.new
      pbwhite("\tMalware Analysis Zoo ::: interactive console")
      pbwhite("\ttype 'help' to view all available commands.\n")

      stty_save = `stty -g`.chomp
      trap("INT") { system("stty", stty_save); exit }
      prompt = white(bold("maz >> "))

      while cmd = Readline.readline("#{prompt}", true).chomp
        if cmd == "exit"
          shutdown
        elsif cmd == "quit"
          shutdown
        elsif cmd == "help"
          help_menu
        elsif cmd == "clear"
          system("clear")
        elsif cmd == "queue"
          if @queue
            @queue.each do |f|
              puts f
            end
          else
            error("the file queue is empty")
          end

        elsif cmd == "tag"
          status("entering tag management")
          manage_tags

        elsif cmd == "recent"
          last = @@Database.view_last
          pbwhite("Last Submission: ")
          pp last

        elsif cmd.include?("search")
          search(cmd)

        elsif cmd == "stats"
          @@Database.stats

        elsif cmd.include?("delete")
          entry = cmd.split(" ")[1].chomp
          status("removing database entry belonging to md5 hash: #{entry}")
          puts @@Database.delete_entry(entry)

        elsif cmd.include?("analyze")
          if cmd.include?("queue")
            @queue.each do |sample|
              @@Analyze.submit(sample)
            end
          else
            file_name = cmd.split(" ")[1]
            @@Analyze.submit(file_name)
          end

        elsif cmd.include?("load")
          queue_add(cmd)

        else
          error("command #{cmd} is not a valid entry.")
        end

      end
    end
  end
end


